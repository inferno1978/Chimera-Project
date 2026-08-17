"""
chimera/modules/subscription_multinode.py
───────────────────────────────────────────────────────────────────────────────
Мульти-нодовые клиентские конфиги для единой подписки (Mode B).

Идея:
  В Mode B (каскад Entry→Exit) сервер уже знает параметры всех exit-нод
  (state.json → chain_nodes[]) и entry mirrors (entry_mirrors.json).
  Этого достаточно, чтобы сгенерировать клиенту ПОЛНЫЙ конфиг с выбором
  ноды прямо в приложении — без изменения серверной топологии:

    • mihomo/Clash Meta YAML (?format=clash) — по образу и подобию
      эталонного конфига проекта: DNS fake-ip + DoH + умный сплит,
      TUN, sniffer, geox-зеркала, rule-providers (Loyalsoldier .txt +
      MetaCubeX .mrs), группы «📍 Выбор ноды» / Auto / Fallback /
      Balance-RR/Hash/Sticky/Weighted / Streaming / Telegram / AI,
      правила (adblock, QUIC-block YouTube, РФ-direct, GEOIP RU).

    • sing-box JSON (?format=singbox, мульти-нодовый) — все ноды как
      outbounds + selector «🎯 Chimera» + urltest «auto», route.final →
      selector. RU-сплит через singbox_client_rulesets.inject_route_rulesets.

    • base64-подписка — vless:// каждой exit-ноды (со своим chain-UUID):
      v2rayNG / Happ / NekoBox сами сгруппируют ссылки и дадут выбор.

  Прямое подключение к exit-нодам идёт под chain-UUID ноды (общим для
  всех пользователей подписки) — per-user учёт трафика работает только
  на каскаде через entry. Это осознанный компромисс (обсуждён с автором):
  конфиг идентичен ручному «кастомному конфигу mihomo», который проект
  поддерживает вручную — теперь он генерируется автоматически.

Включение:
  subscription.json → {"multinode": {"enabled": true|false}}
  Явный ключ приоритетнее; по умолчанию (ключа нет) фича активна при
  install_mode == "B" и наличии хотя бы одной exit-ноды.

Хранение geo-кеша:
  subscription.json → {"multinode": {"geo_cache": {host: {cc, ts}}}}
  ip-api.com, TTL 7 суток, таймаут 4с, при сбое — "🌐".
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import importlib
import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

# ── Пути ─────────────────────────────────────────────────────────────────
_STATE_FILE   = Path("/var/lib/xray-installer/state.json")
_SUB_CONF     = Path("/var/lib/xray-installer/subscription.json")
_MIRRORS_FILE = Path("/var/lib/xray-installer/entry_mirrors.json")

_GEO_CACHE_TTL = 7 * 24 * 3600  # 7 суток
_GEO_TIMEOUT   = 4

# ── Логирование (единый формат с остальными модулями) ────────────────────
import sys

_LOG_FILE = Path("/var/log/chimera.log")

def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [SUBSCRIPTION-MULTINODE] [{level}] {clean}\n")
    except Exception:
        pass


def _core_module():
    """Возвращает модуль chimera._core (lazy import, без circular)."""
    return importlib.import_module("chimera._core")


def _core_call(func_name: str, *args, **kwargs):
    return getattr(_core_module(), func_name)(*args, **kwargs)

# ══════════════════════════════════════════════════════════════════════════
#  STATE / CONF
# ══════════════════════════════════════════════════════════════════════════

def _load_state() -> dict:
    if not _STATE_FILE.exists():
        return {}
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception as e:
        _log("WARN", f"state.json повреждён: {e}")
        return {}


def _load_sub_conf() -> dict:
    if not _SUB_CONF.exists():
        return {}
    try:
        return json.loads(_SUB_CONF.read_text())
    except Exception:
        return {}


def _save_sub_conf(cfg: dict) -> None:
    _SUB_CONF.parent.mkdir(parents=True, exist_ok=True)
    _SUB_CONF.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _SUB_CONF.chmod(0o600)


def _chain_nodes_from_state(state: dict) -> list[dict]:
    """chain_nodes[] + legacy chain_exit_* (тот же формат, что chain_nodes.py)."""
    nodes = state.get("chain_nodes")
    if isinstance(nodes, list) and nodes:
        return [n for n in nodes if isinstance(n, dict) and n.get("host")]
    host = state.get("chain_exit_host", "")
    if host:
        return [{
            "host":    host,
            "port":    state.get("chain_exit_port", 443),
            "uuid":    state.get("chain_exit_uuid", ""),
            "pubkey":  state.get("chain_exit_pubkey", ""),
            "shortid": state.get("chain_exit_shortid", ""),
            "sni":     state.get("chain_exit_sni", ""),
            "fp":      state.get("chain_exit_fp", "chrome"),
        }]
    return []

# ══════════════════════════════════════════════════════════════════════════
#  GEO-IP (ip-api.com + кеш в subscription.json)
# ══════════════════════════════════════════════════════════════════════════

def _flag_emoji(cc: str) -> str:
    """🇩🇪 по ISO-кодy; та же формула, что resources.country_flag_emoji
    (локальная копия — 3 строки, чтобы не тянуть import ради одной функции)."""
    cc = (cc or "").upper().strip()
    if len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc)


def _geo_lookup(host: str) -> str:
    """Country code по IP/домену. Кеш в subscription.json → multinode.geo_cache.
    При любой ошибке возвращает '' (→ флаг 🌐), никогда не бросает."""
    if not host:
        return ""
    # Локальные/приватные адреса не спрашиваем
    if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$)', host):
        return ""
    cfg = _load_sub_conf()
    mn = cfg.setdefault("multinode", {})
    cache = mn.setdefault("geo_cache", {})
    entry = cache.get(host) or {}
    cc = entry.get("cc", "")
    ts = int(entry.get("ts", 0))
    now = int(time.time())
    if cc and now - ts < _GEO_CACHE_TTL:
        return cc
    # Живой запрос
    try:
        url = f"http://ip-api.com/json/{urllib.parse.quote(host)}?fields=status,countryCode"
        req = urllib.request.Request(url, headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=_GEO_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        if data.get("status") == "success" and data.get("countryCode"):
            cc = data["countryCode"].upper()
            cache[host] = {"cc": cc, "ts": now}
            mn["geo_cache"] = cache
            cfg["multinode"] = mn
            _save_sub_conf(cfg)
            return cc
    except Exception as e:
        _log("WARN", f"geo lookup {host}: {e}")
    # Неудача — кешируем пустой результат ТОЛЬКО если до этого страны не
    # знали (старое значение не затираем: лучше показывать устаревший
    # флаг, чем терять его из-за временного сбоя сети/API).
    if not cc:
        cache[host] = {"cc": "", "ts": now}
        mn["geo_cache"] = cache
        cfg["multinode"] = mn
        try:
            _save_sub_conf(cfg)
        except Exception:
            pass
    return ""


def _node_display_name(kind: str, host: str, label: str,
                       counters: dict) -> str:
    """🇩🇪 DE #1 / 🪞 Mirror · label / 🇷🇺 Entry (каскад).
    counters ведёт per-country индексы для exit-нод."""
    cc = _geo_lookup(host)
    flag = _flag_emoji(cc)
    base_cc = cc or "??"
    if kind == "exit":
        if label:
            return f"{flag} {label}"
        n = counters.get(base_cc, 0) + 1
        counters[base_cc] = n
        return f"{flag} {base_cc} #{n}" if n > 1 else f"{flag} {base_cc}"
    if kind == "mirror":
        return f"🪞 {label or 'Mirror'}"
    return f"{flag} Entry ({'каскад' if kind == 'entry_cascade' else 'прямой'})"

# ══════════════════════════════════════════════════════════════════════════
#  ФЛАГ ФИЧИ
# ══════════════════════════════════════════════════════════════════════════

def multinode_status() -> dict:
    """{"enabled": bool, "explicit": bool, "reason": str}.

    Явный ключ multinode.enabled в subscription.json приоритетнее;
    без ключа — авто: install_mode == "B" и есть хотя бы одна exit-нода."""
    state = _load_state()
    cfg = _load_sub_conf()
    mn = cfg.get("multinode") or {}
    exits = _chain_nodes_from_state(state)
    if "enabled" in mn:
        return {
            "enabled": bool(mn.get("enabled")),
            "explicit": True,
            "reason": "явная настройка в subscription.json",
            "exit_count": len(exits),
        }
    active = state.get("install_mode", "A") == "B" and bool(exits)
    reason = ("авто: Mode B, %d exit-нод" % len(exits)) if active else (
        "авто: выключено (%s)" % (
            "Mode A" if state.get("install_mode", "A") != "B"
            else "нет exit-нод в chain_nodes"))
    return {"enabled": active, "explicit": False, "reason": reason,
            "exit_count": len(exits)}


def is_multinode_active() -> bool:
    try:
        return multinode_status()["enabled"]
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════
#  РЕЕСТР НОД
# ══════════════════════════════════════════════════════════════════════════

def _entry_node(state: dict, user: dict) -> Optional[dict]:
    """Основная entry-нода (каскадная в Mode B) по state + user UUID."""
    domain = state.get("domain", "")
    if not domain:
        return None
    proto = state.get("protocol_mode", "reality")
    sni = domain
    if proto == "reality":
        # В Mode B + AWG exit SNI = reality_dest (та же логика, что
        # subscription._resolve_sni — клиент обязан видеть тот же SNI).
        awg = state.get("awg_exit_enabled", False)
        if awg and state.get("install_mode", "A") == "B" and state.get("reality_dest", ""):
            sni = state["reality_dest"].split(":")[0]
    return {
        "kind": "entry_cascade" if state.get("install_mode", "A") == "B" else "entry",
        "uuid":       user.get("uuid", ""),
        "host":       domain,
        "port":       int(state.get("server_port", 443)),
        "pbk":        state.get("public_key", ""),
        "sid":        state.get("short_id", ""),
        "sni":        sni,
        "fp":         state.get("fingerprint", "chrome") or "chrome",
        "flow":       state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision",
        "proto":      proto,
        "path":       state.get("xhttp_path", "/"),
        "xhttp_mode": state.get("xhttp_mode", "stream-up"),
    }


def collect_nodes(user: dict) -> dict:
    """Собирает реестр нод для пользователя.

    Возвращает {"entry": {...}|None, "exits": [...], "mirrors": [...],
                "all": [...]} — each node dict имеет name/kind/uuid/host/
    port/pbk/sid/sni/fp/flow/proto/path/xhttp_mode."""
    state = _load_state()
    counters: dict = {}

    entry = _entry_node(state, user)
    if entry:
        entry["name"] = _node_display_name(
            entry["kind"], entry["host"], "", counters)

    exits: list[dict] = []
    for nd in _chain_nodes_from_state(state):
        node = {
            "kind":       "exit",
            "uuid":       nd.get("uuid", ""),
            "host":       nd.get("host", ""),
            "port":       int(nd.get("port", 443) or 443),
            "pbk":        nd.get("pubkey", ""),
            "sid":        nd.get("shortid", ""),
            "sni":        nd.get("sni", "") or nd.get("host", ""),
            "fp":         nd.get("fp", "chrome") or "chrome",
            "flow":       nd.get("flow", "xtls-rprx-vision") or "xtls-rprx-vision",
            "proto":      nd.get("proto", "reality"),
            "path":       nd.get("path", "/"),
            "xhttp_mode": nd.get("xhttp_mode", "stream-up"),
        }
        if not (node["uuid"] and node["host"] and node["pbk"]):
            continue  # неполная нода — в конфиг её включать нельзя
        node["name"] = _node_display_name(
            "exit", node["host"], nd.get("label", ""), counters)
        exits.append(node)

    mirrors: list[dict] = []
    if _MIRRORS_FILE.exists():
        try:
            mdata = json.loads(_MIRRORS_FILE.read_text())
            for i, m in enumerate(mdata.get("mirrors", []), 1):
                if not m.get("enabled", True):
                    continue
                node = {
                    "kind":       "mirror",
                    "uuid":       user.get("uuid", ""),
                    "host":       m.get("host", ""),
                    "port":       int(m.get("port", 443) or 443),
                    "pbk":        m.get("pbk", ""),
                    "sid":        m.get("sid", ""),
                    "sni":        m.get("sni", ""),
                    "fp":         m.get("fp", "chrome") or "chrome",
                    "flow":       "xtls-rprx-vision",
                    "proto":      "reality",
                    "path":       "/",
                    "xhttp_mode": "stream-up",
                }
                if not (node["host"] and node["pbk"] and node["sni"]):
                    continue
                node["name"] = _node_display_name(
                    "mirror", node["host"], m.get("label", ""), counters)
                mirrors.append(node)
        except Exception as e:
            _log("WARN", f"entry_mirrors.json: {e}")

    # Порядок «all»: exit-ноды первыми (как в эталонном конфиге:
    # зарубежные первыми, RU-каскад в конце), затем entry, затем mirrors.
    all_nodes = exits + ([entry] if entry else []) + mirrors
    return {"entry": entry, "exits": exits, "mirrors": mirrors, "all": all_nodes}

# ══════════════════════════════════════════════════════════════════════════
#  vless:// URI ДЛЯ EXIT-НОД (в base64-подписку)
# ══════════════════════════════════════════════════════════════════════════

def get_multinode_uris(user: dict) -> list[str]:
    """vless:// каждой exit-ноды (chain-UUID ноды, имя с флагом в fragment).
    Mirrors НЕ включаются — их уже добавляет subscription.py отдельно.
    Никогда не бросает исключение."""
    try:
        if not is_multinode_active():
            return []
        reg = collect_nodes(user)
        uris: list[str] = []
        for nd in reg["exits"]:
            try:
                link = _core_call(
                    "_gen_vless_link", nd["host"], nd["uuid"], nd["pbk"],
                    nd["sid"], nd["sni"], nd["fp"], nd["proto"],
                    nd["path"], nd["xhttp_mode"], nd["port"],
                )
            except Exception as e:
                _log("WARN", f"vless link для {nd['name']}: {e}")
                continue
            if not link:
                continue
            base, _, _frag = link.partition("#")
            uris.append(f"{base}#{urllib.parse.quote(nd['name'])}")
        return uris
    except Exception as e:
        _log("WARN", f"get_multinode_uris: {e}")
        return []

# ══════════════════════════════════════════════════════════════════════════
#  MIHOMO / CLASH META YAML (?format=clash)
# ══════════════════════════════════════════════════════════════════════════

def _yq(s: str) -> str:
    """YAML double-quoted string (имена нод содержат эмодзи/пробелы)."""
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def _mihomo_proxy_block(nd: dict, indent: str = "  ") -> list[str]:
    """Один proxies[] элемент для mihomo. Reality и xHTTP варианты."""
    lines = [
        f"{indent}- name: {_yq(nd['name'])}",
        f"{indent}  type: vless",
        f"{indent}  server: {nd['host']}",
        f"{indent}  port: {nd['port']}",
        f"{indent}  ip-version: dual",
        f"{indent}  uuid: {nd['uuid']}",
    ]
    if nd["proto"] == "xhttp":
        lines += [
            f"{indent}  network: http",
            f"{indent}  tls: true",
            f"{indent}  udp: false",
            f"{indent}  http-opts:",
            f"{indent}    path:",
            f"{indent}      - {_yq(nd.get('path', '/'))}",
            f"{indent}    headers:",
            f"{indent}      Host:",
            f"{indent}        - {_yq(nd['sni'] or nd['host'])}",
            f"{indent}  client-fingerprint: {nd['fp']}",
            f"{indent}  servername: {nd['sni'] or nd['host']}",
        ]
    else:
        lines += [
            f"{indent}  network: tcp",
            f"{indent}  tls: true",
            f"{indent}  udp: true",
            f"{indent}  flow: {nd.get('flow') or 'xtls-rprx-vision'}",
            f"{indent}  servername: {nd['sni'] or nd['host']}",
            f"{indent}  reality-opts:",
            f"{indent}    public-key: {nd['pbk']}",
            f"{indent}    short-id: {_yq(nd.get('sid', ''))}",
            f"{indent}  client-fingerprint: {nd['fp']}",
        ]
    return lines


def _is_domain(host: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$', host or ""))


def _node_domains(nodes: list[dict]) -> list[str]:
    """Уникальные домены всех нод (для fake-ip-filter и правил защиты)."""
    seen, out = set(), []
    for nd in nodes:
        for cand in (nd.get("host", ""), nd.get("sni", "")):
            if cand and _is_domain(cand) and cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


# Статический каркас — проверенный эталонный конфиг проекта
# (chimera-nodes-full: Loyalsoldier + MetaCubeX, jsDelivr CDN из РФ).
_GEOX_URLS = """geox-url:
  geoip: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
  asn: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"
"""

_RULE_PROVIDERS = """rule-providers:
  # Блокировка
  reject:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt"
    path: ./ruleset/loyalsoldier/reject.yaml
    interval: 86400
    format: yaml

  # Прокси (зарубежные сайты)
  proxy:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
    path: ./ruleset/loyalsoldier/proxy.yaml
    interval: 86400
    format: yaml

  # Прямые (домашние/локальные)
  direct:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
    path: ./ruleset/loyalsoldier/direct.yaml
    interval: 86400
    format: yaml

  # Private IP (локальная сеть)
  private:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt"
    path: ./ruleset/loyalsoldier/private.yaml
    interval: 86400
    format: yaml

  # GFWList (заблокированные домены)
  gfw:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt"
    path: ./ruleset/loyalsoldier/gfw.yaml
    interval: 86400
    format: yaml

  # Greatfire (китайские заблокированные домены → proxy)
  greatfire:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt"
    path: ./ruleset/loyalsoldier/greatfire.yaml
    interval: 86400
    format: yaml

  # Telegram CIDR (Loyalsoldier — резерв к MetaCubeX telegram-ip)
  telegramcidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt"
    path: ./ruleset/loyalsoldier/telegramcidr.yaml
    interval: 86400
    format: yaml

  # Китайские IP-диапазоны (Loyalsoldier — резерв к GEOIP,CN)
  cncidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
    path: ./ruleset/loyalsoldier/cncidr.yaml
    interval: 86400
    format: yaml

  # Приложения (Steam, Battle.net и т.д.)
  applications:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt"
    path: ./ruleset/loyalsoldier/applications.yaml
    interval: 86400
    format: yaml

  # ── Стриминг + Telegram + AI (MetaCubeX .mrs) ──
  youtube-domains:
    type: http
    behavior: domain
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/youtube.mrs"
    path: ./ruleset/metacubex/youtube-domains.mrs
    interval: 86400
    format: mrs

  netflix-domains:
    type: http
    behavior: domain
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/netflix.mrs"
    path: ./ruleset/metacubex/netflix-domains.mrs
    interval: 86400
    format: mrs

  # Netflix IP (CDN-диапазоны Netflix — защита от DNS-подмены)
  netflix-ip:
    type: http
    behavior: ipcidr
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/netflix.mrs"
    path: ./ruleset/metacubex/netflix-ip.mrs
    interval: 86400
    format: mrs

  twitch-domains:
    type: http
    behavior: domain
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/twitch.mrs"
    path: ./ruleset/metacubex/twitch-domains.mrs
    interval: 86400
    format: mrs

  spotify-domains:
    type: http
    behavior: domain
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/spotify.mrs"
    path: ./ruleset/metacubex/spotify-domains.mrs
    interval: 86400
    format: mrs

  # Disney+ домены (стриминг)
  disney-domains:
    type: http
    behavior: domain
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/disney.mrs"
    path: ./ruleset/metacubex/disney-domains.mrs
    interval: 86400
    format: mrs

  tiktok-domains:
    type: http
    behavior: domain
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/tiktok.mrs"
    path: ./ruleset/metacubex/tiktok-domains.mrs
    interval: 86400
    format: mrs

  telegram-domains:
    type: http
    behavior: domain
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/telegram.mrs"
    path: ./ruleset/metacubex/telegram-domains.mrs
    interval: 86400
    format: mrs

  telegram-ip:
    type: http
    behavior: ipcidr
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/telegram.mrs"
    path: ./ruleset/metacubex/telegram-ip.mrs
    interval: 86400
    format: mrs

  openai-domains:
    type: http
    behavior: domain
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/openai.mrs"
    path: ./ruleset/metacubex/openai-domains.mrs
    interval: 86400
    format: mrs

  # РФ подсети (IPv4 + IPv6, бинарный .mrs)
  ru-ripe-subnets:
    type: http
    behavior: ipcidr
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/ru.mrs"
    path: ./ruleset/metacubex/ru-ripe-subnets.mrs
    interval: 86400
    format: mrs
"""

_RULES_STATIC_HEAD = """rules:
  # ── Блокировка рекламы и телеметрии ──
  - DOMAIN-SUFFIX,doubleclick.net,REJECT
  - DOMAIN-SUFFIX,googlesyndication.com,REJECT
  - DOMAIN-SUFFIX,googleadservices.com,REJECT
  - DOMAIN-SUFFIX,googletagmanager.com,REJECT
  - DOMAIN-SUFFIX,googletagservices.com,REJECT
  - DOMAIN-SUFFIX,adservice.google.com,REJECT
  - DOMAIN-SUFFIX,adsystem.amazon.com,REJECT
  - DOMAIN-SUFFIX,adnxs.com,REJECT
  - DOMAIN-SUFFIX,criteo.com,REJECT
  - DOMAIN-SUFFIX,criteo.net,REJECT
  - DOMAIN-SUFFIX,2mdn.net,REJECT
  - DOMAIN-SUFFIX,moatads.com,REJECT
  - DOMAIN-SUFFIX,adsrvr.org,REJECT
  - DOMAIN-SUFFIX,rubiconproject.com,REJECT
  - DOMAIN-SUFFIX,pubmatic.com,REJECT
  - DOMAIN-SUFFIX,openx.net,REJECT
  - DOMAIN-SUFFIX,quantserve.com,REJECT
  - DOMAIN-SUFFIX,scorecardresearch.com,REJECT
  - DOMAIN-SUFFIX,hotjar.com,REJECT
  - DOMAIN-SUFFIX,segment.io,REJECT
  - DOMAIN-SUFFIX,amplitude.com,REJECT
  - DOMAIN-SUFFIX,mixpanel.com,REJECT
  - DOMAIN-SUFFIX,clarity.ms,REJECT
  - DOMAIN-SUFFIX,fullstory.com,REJECT
  - DOMAIN-SUFFIX,chartbeat.com,REJECT
  - DOMAIN-KEYWORD,adservice,REJECT
  - DOMAIN-KEYWORD,telemetry,REJECT
  - DOMAIN-SUFFIX,vortex.data.microsoft.com,REJECT
  - DOMAIN-SUFFIX,telemetry.microsoft.com,REJECT
  - DOMAIN-SUFFIX,settings-win.data.microsoft.com,REJECT
  - DOMAIN-SUFFIX,events.data.microsoft.com,REJECT
  - DOMAIN-SUFFIX,msedge.api.cdp.microsoft.com,REJECT
  - DOMAIN-SUFFIX,browser.events.data.microsoft.com,REJECT
  - DOMAIN-SUFFIX,connect.facebook.net,REJECT
  - DOMAIN-SUFFIX,graph.facebook.com,REJECT
  - DOMAIN-KEYWORD,facebookpixel,REJECT
  - DOMAIN-SUFFIX,connectivitycheck.gstatic.com,REJECT
  - DOMAIN-SUFFIX,safebrowsing.googleapis.com,REJECT
  - DOMAIN-SUFFIX,safebrowsing.google.com,REJECT
  - DOMAIN-SUFFIX,clientservices.googleapis.com,REJECT
  - DOMAIN-SUFFIX,update.googleapis.com,REJECT
  - DOMAIN-SUFFIX,optimizationguide-pa.googleapis.com,REJECT
  - DOMAIN-SUFFIX,sls.update.microsoft.com,REJECT
  - DOMAIN-SUFFIX,stats.microsoft.com,REJECT
  - DOMAIN-KEYWORD,analytics,REJECT
  - DOMAIN-KEYWORD,tracker,REJECT
  - DOMAIN-SUFFIX,sentry.io,REJECT
  - DOMAIN-SUFFIX,bugsnag.com,REJECT

  # ── Гео-блокировка рекламы ──
  - GEOSITE,category-ads-all,REJECT

  # ── Внешние списки: блокировка (Loyalsoldier) ──
  - RULE-SET,reject,REJECT
"""

_RULES_STATIC_TAIL = """  # ── AI сервисы (домены + auto-update) ──
  - RULE-SET,openai-domains,AI
  - DOMAIN-SUFFIX,claude.ai,AI
  - DOMAIN-SUFFIX,anthropic.com,AI
  - DOMAIN-SUFFIX,gemini.google.com,AI
  - DOMAIN-SUFFIX,bard.google.com,AI
  - DOMAIN-SUFFIX,copilot.microsoft.com,AI
  - DOMAIN-SUFFIX,perplexity.ai,AI
  - DOMAIN-SUFFIX,midjourney.com,AI
  - DOMAIN-SUFFIX,stability.ai,AI
  - DOMAIN-SUFFIX,huggingface.co,AI
  - DOMAIN-SUFFIX,groq.com,AI
  - DOMAIN-SUFFIX,mistral.ai,AI
  - DOMAIN-SUFFIX,deepseek.com,AI
  - DOMAIN-SUFFIX,x.ai,AI
  - DOMAIN-SUFFIX,grok.com,AI

  # ── YouTube: блокировка QUIC (UDP/443) — Reality = TCP-only,
  #    QUIC оборачивается в TCP (head-of-line blocking). REJECT UDP/443
  #    → браузер мгновенно откатывается на стабильный TCP/HTTP2. ──
  - AND,((DOMAIN-SUFFIX,googlevideo.com),(NETWORK,udp),(DST-PORT,443)),REJECT
  - AND,((DOMAIN-SUFFIX,youtube.com),(NETWORK,udp),(DST-PORT,443)),REJECT
  - AND,((DOMAIN-SUFFIX,ytimg.com),(NETWORK,udp),(DST-PORT,443)),REJECT
  - AND,((DOMAIN-SUFFIX,ggpht.com),(NETWORK,udp),(DST-PORT,443)),REJECT
  - AND,((DOMAIN-SUFFIX,youtu.be),(NETWORK,udp),(DST-PORT,443)),REJECT
  - AND,((DOMAIN-SUFFIX,youtube-nocookie.com),(NETWORK,udp),(DST-PORT,443)),REJECT
  - AND,((DOMAIN-SUFFIX,youtubei.googleapis.com),(NETWORK,udp),(DST-PORT,443)),REJECT

  # ── Стриминг ──
  - RULE-SET,youtube-domains,Streaming
  - RULE-SET,netflix-domains,Streaming
  - RULE-SET,netflix-ip,Streaming
  - RULE-SET,twitch-domains,Streaming
  - RULE-SET,spotify-domains,Streaming
  - RULE-SET,tiktok-domains,Streaming
  - RULE-SET,disney-domains,Streaming
  - DOMAIN-SUFFIX,hbomax.com,Streaming
  - DOMAIN-SUFFIX,primevideo.com,Streaming
  - DOMAIN-SUFFIX,hulu.com,Streaming

  # ── Telegram ──
  - RULE-SET,telegram-domains,Telegram
  - RULE-SET,telegram-ip,Telegram
  - RULE-SET,telegramcidr,Telegram

  # ── Яндекс ──
  - DOMAIN-KEYWORD,yandex,DIRECT
  - DOMAIN-SUFFIX,yandex.ru,DIRECT
  - DOMAIN-SUFFIX,yandex.net,DIRECT
  - DOMAIN-SUFFIX,yandex.com,DIRECT
  - DOMAIN-SUFFIX,ya.ru,DIRECT
  - DOMAIN-SUFFIX,yastatic.net,DIRECT
  - DOMAIN-SUFFIX,mc.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,mc.webvisor.org,DIRECT
  - DOMAIN-SUFFIX,mc.webvisor.com,DIRECT
  - DOMAIN-SUFFIX,an.yandex.ru,DIRECT

  # ── VK и Mail.ru ──
  - DOMAIN-SUFFIX,vk.com,DIRECT
  - DOMAIN-SUFFIX,vk.ru,DIRECT
  - DOMAIN-SUFFIX,vkuseraudio.net,DIRECT
  - DOMAIN-SUFFIX,vkuserapi.net,DIRECT
  - DOMAIN-SUFFIX,vk.me,DIRECT
  - DOMAIN-SUFFIX,vk-portal.net,DIRECT
  - DOMAIN-SUFFIX,vk-cdn.net,DIRECT
  - DOMAIN-SUFFIX,userapi.com,DIRECT
  - DOMAIN-SUFFIX,mail.ru,DIRECT
  - DOMAIN-SUFFIX,ok.ru,DIRECT

  # ── Банки ──
  - DOMAIN-SUFFIX,sberbank.ru,DIRECT
  - DOMAIN-SUFFIX,tbank.ru,DIRECT
  - DOMAIN-SUFFIX,tinkoff.ru,DIRECT
  - DOMAIN-SUFFIX,alfabank.ru,DIRECT
  - DOMAIN-SUFFIX,raiffeisen.ru,DIRECT
  - DOMAIN-SUFFIX,vtb.ru,DIRECT
  - DOMAIN-SUFFIX,gazprombank.ru,DIRECT
  - DOMAIN-SUFFIX,open.ru,DIRECT
  - DOMAIN-SUFFIX,open-broker.ru,DIRECT
  - DOMAIN-SUFFIX,rshb.ru,DIRECT
  - DOMAIN-SUFFIX,psb.ru,DIRECT
  - DOMAIN-SUFFIX,uralsib.ru,DIRECT
  - DOMAIN-SUFFIX,absolutbank.ru,DIRECT
  - DOMAIN-SUFFIX,sovcombank.ru,DIRECT
  - DOMAIN-SUFFIX,creditcard.ru,DIRECT

  # ── Магазины ──
  - DOMAIN-SUFFIX,ozon.ru,DIRECT
  - DOMAIN-SUFFIX,wildberries.ru,DIRECT
  - DOMAIN-SUFFIX,aliexpress.ru,DIRECT
  - DOMAIN-SUFFIX,aliexpress.com,DIRECT
  - DOMAIN-SUFFIX,alibaba.com,DIRECT
  - DOMAIN-SUFFIX,mvideo.ru,DIRECT
  - DOMAIN-SUFFIX,eldorado.ru,DIRECT
  - DOMAIN-SUFFIX,dns-shop.ru,DIRECT
  - DOMAIN-SUFFIX,sportmaster.ru,DIRECT
  - DOMAIN-SUFFIX,cian.ru,DIRECT
  - DOMAIN-SUFFIX,auto.ru,DIRECT
  - DOMAIN-SUFFIX,drom.ru,DIRECT
  - DOMAIN-SUFFIX,avito.ru,DIRECT
  - DOMAIN-KEYWORD,avito,DIRECT
  - DOMAIN-SUFFIX,edadeal.ru,DIRECT

  # ── Государство ──
  - DOMAIN-SUFFIX,gosuslugi.ru,DIRECT
  - DOMAIN-SUFFIX,gov.ru,DIRECT
  - DOMAIN-SUFFIX,nalog.gov.ru,DIRECT
  - DOMAIN-SUFFIX,api-interface.nalog.ru,DIRECT
  - DOMAIN-SUFFIX,pfr.gov.ru,DIRECT
  - DOMAIN-SUFFIX,fssprus.ru,DIRECT
  - DOMAIN-SUFFIX,mos.ru,DIRECT
  - DOMAIN-SUFFIX,fastbox.mos.ru,DIRECT
  - DOMAIN-SUFFIX,brave.nalog.ru,DIRECT
  - DOMAIN-SUFFIX,brave.gosuslugi.ru,DIRECT
  - DOMAIN-SUFFIX,gibdd.ru,DIRECT

  # ── Операторы и медиа ──
  - DOMAIN-SUFFIX,mts.ru,DIRECT
  - DOMAIN-SUFFIX,tele2.ru,DIRECT
  - DOMAIN-SUFFIX,beeline.ru,DIRECT
  - DOMAIN-SUFFIX,megafon.ru,DIRECT
  - DOMAIN-SUFFIX,rt.ru,DIRECT
  - DOMAIN-SUFFIX,rostelecom.ru,DIRECT
  - DOMAIN-SUFFIX,dom.ru,DIRECT
  - DOMAIN-SUFFIX,tricolor.tv,DIRECT
  - DOMAIN-SUFFIX,ufanet.ru,DIRECT
  - DOMAIN-SUFFIX,kinopoisk.ru,DIRECT
  - DOMAIN-KEYWORD,kinopoisk,DIRECT
  - DOMAIN-SUFFIX,1tv.ru,DIRECT
  - DOMAIN-SUFFIX,firstchannel.ru,DIRECT
  - DOMAIN-SUFFIX,ria.ru,DIRECT
  - DOMAIN-SUFFIX,tass.ru,DIRECT
  - DOMAIN-SUFFIX,lenta.ru,DIRECT
  - DOMAIN-SUFFIX,rambler.ru,DIRECT
  - DOMAIN-KEYWORD,rambler,DIRECT
  - DOMAIN-SUFFIX,lostfilm.tv,DIRECT

  # ── IT ──
  - DOMAIN-SUFFIX,habr.ru,DIRECT
  - DOMAIN-SUFFIX,habr.com,DIRECT
  - DOMAIN-SUFFIX,4pda.to,DIRECT
  - DOMAIN-SUFFIX,4pda.ru,DIRECT
  - DOMAIN-SUFFIX,litres.ru,DIRECT
  - DOMAIN-SUFFIX,bookmate.ru,DIRECT
  - DOMAIN-SUFFIX,mybook.ru,DIRECT
  - DOMAIN-SUFFIX,studfile.net,DIRECT
  - DOMAIN-SUFFIX,garant.ru,DIRECT
  - DOMAIN-SUFFIX,consultant.ru,DIRECT
  - DOMAIN-SUFFIX,msu.ru,DIRECT
  - DOMAIN-SUFFIX,spbu.ru,DIRECT
  - DOMAIN-SUFFIX,mtuci.ru,DIRECT
  - DOMAIN-SUFFIX,hse.ru,DIRECT
  - DOMAIN-SUFFIX,mipt.ru,DIRECT
  - DOMAIN-SUFFIX,urfu.ru,DIRECT
  - DOMAIN-SUFFIX,kpfu.ru,DIRECT
  - DOMAIN-SUFFIX,mgimo.ru,DIRECT
  - DOMAIN-SUFFIX,bmstu.ru,DIRECT
  - DOMAIN-SUFFIX,2ip.ru,DIRECT
  - DOMAIN-SUFFIX,2ip.io,DIRECT
  - DOMAIN-SUFFIX,2gis.ru,DIRECT
  - DOMAIN-SUFFIX,rutracker.org,DIRECT
  - DOMAIN-SUFFIX,rutracker.ru,DIRECT
  - DOMAIN-SUFFIX,dtf.ru,DIRECT
  - DOMAIN-SUFFIX,stopgame.ru,DIRECT
  - DOMAIN-SUFFIX,igromania.ru,DIRECT
  - DOMAIN-SUFFIX,kanobu.ru,DIRECT
  - DOMAIN-SUFFIX,gg.ru,DIRECT
  - DOMAIN-SUFFIX,e1.ru,DIRECT
  - DOMAIN-SUFFIX,nn.ru,DIRECT
  - DOMAIN-SUFFIX,rugion.ru,DIRECT
  - DOMAIN-SUFFIX,skbkontur.ru,DIRECT
  - DOMAIN-SUFFIX,kontur.ru,DIRECT

  # ── Внешние списки: прямые и приложения (Loyalsoldier) ──
  - RULE-SET,applications,DIRECT
  - RULE-SET,direct,DIRECT
  - RULE-SET,private,DIRECT

  # ── GFW + Greatfire (заблокированные домены → прокси) ──
  - RULE-SET,gfw,Proxy
  - RULE-SET,greatfire,Proxy

  # ── Внешний список: прокси-домены (Loyalsoldier) ──
  - RULE-SET,proxy,Proxy

  # ── Гео-маршрутизация ──
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT

  # ── РФ подсети из ru.mrs (явный rule-provider, ~25000 CIDR) ──
  - RULE-SET,ru-ripe-subnets,DIRECT

  # ── Fallback: встроенный GeoIP ──
  - GEOIP,RU,DIRECT

  # ── Всё остальное — через прокси ──
  - MATCH,Proxy
"""


def build_mihomo_config(user: dict) -> str:
    """Полный mihomo/Clash Meta YAML по эталонному конфигу проекта.

    Динамика: proxies (entry + exits + mirrors), группы, домены нод в
    dns.fake-ip-filter / nameserver-policy / правилах защиты. Остальное —
    статический проверенный каркас. При < 2 нод возвращается упрощённый
    single-proxy конфиг (фича всё равно неактивна)."""
    try:
        reg = collect_nodes(user)
        nodes = reg["all"]
        if not nodes:
            return ""
        exits = reg["exits"]
        domains = _node_domains(nodes)
        exit_names = [n["name"] for n in exits]
        all_names = [n["name"] for n in nodes]

        lines: list[str] = []
        lines += [
            "# ═══════════════════════════════════════════════════════════════════",
            "#  Chimera Project — auto-generated mihomo config",
            f"#  {len(exits)} exit-нод + entry" + (" + mirrors" if reg["mirrors"] else ""),
            "# ═══════════════════════════════════════════════════════════════════",
            "",
            "profile:",
            "  store-selected: true",
            "  store-fake-ip: true",
            "",
        ]

        # ── DNS ──────────────────────────────────────────────────────────
        lines += [
            "dns:",
            "  enable: true",
            "  listen: 0.0.0.0:1053",
            "  ipv6: true",
            "  prefer-h3: true",
            "  cache-algorithm: arc",
            "  enhanced-mode: fake-ip",
            "  fake-ip-range: 198.18.0.1/16",
            "  fake-ip-range-ipv6: fc00::/18",
            "  fake-ip-filter:",
            '    - "*.lan"',
            '    - "*.local"',
            '    - "*.localhost"',
            '    - "+.stun.*.*"',
            '    - "+.stun.*.*.*"',
            '    - "time.*.com"',
            '    - "ntp.*.com"',
            '    - "time.*.gov"',
            '    - "time.*.apple.com"',
            '    - "hoster-nl.example.tencent.com"',
            '    - "time.nist.gov"',
            '    - "+.msftconnecttest.com"',
            '    - "+.msftncsi.com"',
            '    - "dns.msftncsi.com"',
            '    - "localhost.ptlogin2.qq.com"',
            '    - "+.2ip.ru"',
            '    - "+.2ip.io"',
        ]
        for d in domains:
            lines.append(f'    - "+.{d}"')
        lines += [
            "  proxy-server-nameserver:",
            "    - https://1.1.1.1/dns-query",
            "    - https://8.8.8.8/dns-query",
            "  default-nameserver:",
            "    - 1.1.1.1",
            "    - 8.8.8.8",
            "  nameserver:",
            "    - https://1.1.1.1/dns-query",
            "    - https://8.8.8.8/dns-query",
            "  fallback:",
            "    - https://1.1.1.1/dns-query",
            "    - https://8.8.8.8/dns-query",
            "  fallback-filter:",
            "    geoip: true",
            "    geoip-code: RU",
            "    ipcidr:",
            "      - 240.0.0.0/4",
            "  # Умный сплит DNS: RU-домены резолвим через Яндекс DoH",
            "  nameserver-policy:",
            '    "geosite:category-ads-all":',
            "      - rcode://success",
            '    "+.ru,+.su,+.рф":',
            "      - https://dns.yandex.ru/dns-query",
            "      - 77.88.8.8",
        ]
        for d in domains:
            lines.append(f'    "+.{d}":')
            lines.append("      - https://1.1.1.1/dns-query")
        lines += [
            "",
            "tun:",
            "  enable: true",
            "  stack: mixed",
            "  dns-hijack:",
            "    - any:53",
            "    - tcp://any:53",
            "  auto-route: true",
            "  auto-detect-interface: true",
            "  strict-route: true",
            "",
            "allow-lan: false",
            "mode: rule",
            "log-level: warning",
            "ipv6: true",
            "unified-delay: true",
            "tcp-concurrent: true",
            "geodata-mode: true",
            "geo-auto-update: true",
            "geo-update-interval: 24",
            "find-process-mode: always",
            "global-client-fingerprint: firefox",
            "keep-alive-interval: 30",
            "keep-alive-idle: 600",
            "",
            _GEOX_URLS,
            "sniffer:",
            "  enable: true",
            "  sniff:",
            "    HTTP:",
            "      ports:",
            "        - 80",
            "        - 8080-8880",
            "      override-destination: true",
            "    TLS:",
            "      ports:",
            "        - 443",
            "        - 8443",
            "    QUIC:",
            "      ports:",
            "        - 443",
            "        - 8443",
            "",
            _RULE_PROVIDERS,
            "",
            "# ── Прокси-ноды ──",
            "proxies:",
        ]
        for nd in nodes:
            lines += _mihomo_proxy_block(nd)

        # ── Группы ───────────────────────────────────────────────────────
        lines += ["", "proxy-groups:"]
        if exits:
            auto_balance = ["Auto", "Fallback", "Balance-RR", "Balance-Hash",
                            "Balance-Sticky", "Balance-Weighted"]
            lines += [
                "  # 📍 Ручной выбор ноды (tap → список всех нод + опции)",
                f"  - name: {_yq('📍 Выбор ноды')}",
                "    type: select",
                "    proxies:",
            ]
            for nm in exit_names:
                lines.append(f"      - {_yq(nm)}")
            entry = reg["entry"]
            if entry:
                lines.append(f"      - {_yq(entry['name'])}")
            for nm in [m["name"] for m in reg["mirrors"]]:
                lines.append(f"      - {_yq(nm)}")
            for nm in auto_balance:
                lines.append(f"      - {nm}")

            lines += [
                "",
                "  # Главная группа — на неё ссылаются все rules",
                f"  - name: {_yq('Proxy')}",
                "    type: select",
                "    proxies:",
                f"      - {_yq('📍 Выбор ноды')}",
            ]
            for nm in auto_balance:
                lines.append(f"      - {nm}")
            for nm in all_names:
                lines.append(f"      - {_yq(nm)}")

            lines += [
                "",
                "  # Авто по пингу (каждые 5 мин, tolerance 50мс)",
                f"  - name: {_yq('Auto')}",
                "    type: url-test",
                "    proxies:",
            ]
            for nm in exit_names:
                lines.append(f"      - {_yq(nm)}")
            lines += [
                '    url: "https://www.gstatic.com/generate_204"',
                "    interval: 300",
                "    tolerance: 50",
                "    lazy: true",
                "",
                "  # Мгновенное переключение при падении (проверка каждую 1 мин)",
                f"  - name: {_yq('Fallback')}",
                "    type: fallback",
                "    proxies:",
            ]
            for nm in exit_names:
                lines.append(f"      - {_yq(nm)}")
            lines += [
                '    url: "https://www.gstatic.com/generate_204"',
                "    interval: 60",
                "    lazy: true",
                "",
                "  # Балансировка 1: Round-Robin — равномерное распределение",
                f"  - name: {_yq('Balance-RR')}",
                "    type: load-balance",
                "    proxies:",
            ]
            for nm in exit_names:
                lines.append(f"      - {_yq(nm)}")
            lines += [
                "    strategy: round-robin",
                '    url: "https://cp.cloudflare.com/generate_204"',
                "    interval: 300",
                "    lazy: true",
                "",
                "  # Балансировка 2: Consistent Hashing — один домен = одна нода",
                f"  - name: {_yq('Balance-Hash')}",
                "    type: load-balance",
                "    proxies:",
            ]
            for nm in exit_names:
                lines.append(f"      - {_yq(nm)}")
            lines += [
                "    strategy: consistent-hashing",
                '    url: "https://cp.cloudflare.com/generate_204"',
                "    interval: 300",
                "    lazy: true",
                "",
                "  # Балансировка 3: Sticky Sessions — прилипание до сбоя",
                f"  - name: {_yq('Balance-Sticky')}",
                "    type: load-balance",
                "    proxies:",
            ]
            for nm in exit_names:
                lines.append(f"      - {_yq(nm)}")
            lines += [
                "    strategy: sticky-sessions",
                '    url: "https://cp.cloudflare.com/generate_204"',
                "    interval: 300",
                "    lazy: true",
                "",
                "  # Балансировка 4: Weighted — первая нода с двойным весом",
                f"  - name: {_yq('Balance-Weighted')}",
                "    type: load-balance",
                "    proxies:",
            ]
            # Дублируем первую exit-ноду для двойного веса
            if exit_names:
                lines.append(f"      - {_yq(exit_names[0])}")
            for nm in exit_names:
                lines.append(f"      - {_yq(nm)}")
            lines += [
                "    strategy: round-robin",
                '    url: "https://cp.cloudflare.com/generate_204"',
                "    interval: 300",
                "    lazy: true",
            ]

            # Streaming / Telegram / AI (+авто-подгруппы)
            for gname in ("Streaming", "Telegram", "AI"):
                lines += [
                    "",
                    f"  - name: {_yq(gname)}",
                    "    type: select",
                    "    proxies:",
                    f"      - {_yq(exit_names[0])}",
                    f"      - {_yq(gname + '-Auto')}",
                ]
                for nm in exit_names[1:]:
                    lines.append(f"      - {_yq(nm)}")
                lines.append(f"      - {_yq('Proxy')}")
                lines += [
                    "",
                    f"  - name: {_yq(gname + '-Auto')}",
                    "    type: url-test",
                    "    proxies:",
                ]
                for nm in exit_names:
                    lines.append(f"      - {_yq(nm)}")
                lines += [
                    '    url: "https://www.gstatic.com/generate_204"',
                    "    interval: 300",
                    "    tolerance: 80",
                    "    lazy: true",
                ]
        else:
            # Упрощённая структура (Mode A / нет exit-нод): Proxy select.
            lines += [
                f"  - name: {_yq('Proxy')}",
                "    type: select",
                "    proxies:",
            ]
            for nm in all_names:
                lines.append(f"      - {_yq(nm)}")

        # ── Правила ──────────────────────────────────────────────────────
        lines += ["", _RULES_STATIC_HEAD]
        if domains:
            lines.append("  # ── Защита прокси-доменов (все ноды) ──")
            for d in domains:
                lines.append(f"  - DOMAIN-SUFFIX,{d},Proxy")
            lines.append("")
        lines.append(_RULES_STATIC_TAIL)

        return "\n".join(lines) + "\n"
    except Exception as e:
        _log("ERROR", f"build_mihomo_config: {e}")
        return ""

# ══════════════════════════════════════════════════════════════════════════
#  SING-BOX JSON (?format=singbox — мульти-нодовый)
# ══════════════════════════════════════════════════════════════════════════

SELECTOR_TAG = "🎯 Chimera"
URLTEST_TAG  = "auto"
STREAMING_TAG = "🎬 Streaming"
TELEGRAM_TAG  = "✈️ Telegram"
AI_TAG        = "🤖 AI"
DIRECT_TAG    = "direct"
BLOCK_TAG     = "block"
DNS_OUT_TAG   = "dns-out"


def _singbox_vless_outbound(nd: dict) -> dict:
    """sing-box vless outbound (Reality или xHTTP)."""
    ob: dict = {
        "type": "vless",
        "tag": nd["name"],
        "server": nd["host"],
        "server_port": nd["port"],
        "uuid": nd["uuid"],
    }
    if nd["proto"] == "xhttp":
        ob["transport"] = {"type": "http", "path": nd.get("path", "/")}
        ob["tls"] = {
            "enabled": True,
            "server_name": nd["sni"] or nd["host"],
            "utls": {"enabled": True, "fingerprint": nd["fp"]},
        }
    else:
        if nd.get("flow"):
            ob["flow"] = nd["flow"]
        ob["tls"] = {
            "enabled": True,
            "server_name": nd["sni"] or nd["host"],
            "utls": {"enabled": True, "fingerprint": nd["fp"]},
            "reality": {
                "enabled": True,
                "public_key": nd["pbk"],
                "short_id": nd.get("sid", ""),
            },
        }
    return ob


# ── Rule-sets (sing-box 1.11.x, .srs формат, SagerNet/sing-geosite+geoip) ──
# Источник: https://github.com/SagerNet/sing-geosite (rule-set branch, .srs)
#           https://github.com/SagerNet/sing-geoip   (rule-set branch, .srs)
# Бинарный .srs формат — компактнее и быстрее JSON.
# jsDelivr CDN (testingcf — Cloudflare-backed, доступен из РФ).
_SINGBOX_RULESET_DEFS = [
    # Стриминг
    ("geosite-youtube",    "geosite", "youtube"),
    ("geosite-netflix",    "geosite", "netflix"),
    ("geosite-twitch",    "geosite", "twitch"),
    ("geosite-disney",    "geosite", "disney"),
    ("geosite-spotify",   "geosite", "spotify"),
    ("geosite-tiktok",    "geosite", "tiktok"),
    # Telegram
    ("geosite-telegram",  "geosite", "telegram"),
    ("geoip-telegram",    "geoip",   "telegram"),
    # AI
    ("geosite-openai",    "geosite", "openai"),
    # РФ-direct
    ("geosite-ru",        "geosite", "ru"),
    ("geosite-category-ads-all", "geosite", "category-ads-all"),
    ("geoip-ru",          "geoip",   "ru"),
    # Private IP (LAN)
    ("geoip-private",     "geoip",   "private"),
]


def _singbox_ruleset_definitions() -> list[dict]:
    """Генерирует route.rule_set[] — remote .srs с jsDelivr CDN.
    download_detour: 'direct' — иначе хендшейк до создания proxy outbound."""
    out = []
    for tag, kind, name in _SINGBOX_RULESET_DEFS:
        url = (f"https://testingcf.jsdelivr.net/gh/SagerNet/sing-{kind}"
               f"@rule-set/{kind}-{name}.srs")
        out.append({
            "type": "remote",
            "tag": tag,
            "format": "binary",
            "url": url,
            "download_detour": DIRECT_TAG,
            "update_interval": "1d",
        })
    return out


def _singbox_rules() -> list[dict]:
    """Маршруты: DNS-hijack → adblock REJECT → Streaming → Telegram → AI →
    RU-direct → private-direct → final=selector.

    Возвращает route.rules[]. Поле `action: "route"` — обязательно с 1.11.0
    (без него deprecated warning)."""
    return [
        # 1. DNS-перехват (для fake-ip)
        {"protocol": "dns", "action": "hijack-dns"},

        # 2. Блокировка рекламы (rule-set → reject)
        {"rule_set": "geosite-category-ads-all",
         "action": "reject"},

        # 3. Защита прокси-доменов (нельзя пускать через прокси сам домен
        # сервера — иначе хендшейк разорвётся). Добавляется динамически ниже.

        # 4. Стриминг → Streaming-группа
        {"rule_set": ["geosite-youtube", "geosite-netflix",
                      "geosite-twitch", "geosite-disney",
                      "geosite-spotify", "geosite-tiktok"],
         "action": "route", "outbound": STREAMING_TAG},

        # 5. Telegram → Telegram-группа (домены + IP)
        {"rule_set": ["geosite-telegram", "geoip-telegram"],
         "action": "route", "outbound": TELEGRAM_TAG},

        # 6. AI сервисы → AI-группа
        {"rule_set": "geosite-openai",
         "action": "route", "outbound": AI_TAG},

        # 7. РФ-домены → direct (мимо VPN)
        {"rule_set": "geosite-ru",
         "action": "route", "outbound": DIRECT_TAG},

        # 8. РФ IP → direct
        {"rule_set": "geoip-ru",
         "action": "route", "outbound": DIRECT_TAG},

        # 9. Private/LAN IP → direct
        {"rule_set": "geoip-private",
         "action": "route", "outbound": DIRECT_TAG},
    ]


def build_singbox_config(user: dict, extra_outbounds: Optional[list] = None) -> str:
    """Полный мульти-нодовый sing-box JSON (sing-box 1.11.x) по эталону mihomo.

    Структура:
      • DNS: fake-ip + DoH 1.1.1.1 (через proxy) + 8.8.8.8 fallback + локальная
        для outbound:any (чтобы прокси-ноды могли резолвить свои домены).
      • Inbounds: TUN mixed (auto_route + strict_route).
      • Outbounds: все ноды (vless Reality/xHTTP) + сателлиты +
        selector «🎯 Chimera» + urltest «auto» + Streaming/Telegram/AI
        (каждая со своим urltest «*-auto») + direct/block/dns-out.
      • Route: rule_set (12 .srs с jsDelivr CDN) + rules (DNS-hijack →
        adblock REJECT → Streaming/Telegram/AI → RU-direct → private-direct).
        final → selector.
      • Experimental: clash_api (127.0.0.1:9090) + cache_file (persist selector
        choices + fakeip mappings).

    extra_outbounds — сателлитные outbounds из реестра подписки
    (trojan/anytls/tuic/...). Добавляются в outbounds и в selector.

    Возвращает "" если нод нет вообще — caller откатывается на старый
    single-outbound конфиг.

    Совместимость:
      • sing-box 1.11.x — целевая версия (использует action:"route" + rule_set).
      • 1.10.x — работает (action field default "route", deprecated warning).
      • 1.12+ — будет работать (rule_set + action — forward-compatible,
        geosite/geoip direct rules не используются).
    """
    try:
        reg = collect_nodes(user)
        nodes = reg["all"]
        if not nodes:
            return ""

        # ── Outbounds: ноды + сателлиты + служебные ────────────────────
        node_outbounds: list[dict] = []
        for nd in nodes:
            node_outbounds.append(_singbox_vless_outbound(nd))

        # Сателлитные outbounds (trojan/anytls/tuic/...) — добавляем в общий
        # список, но не в selector (т.к. их теги не наши ноды).
        extra_tags: list[str] = []
        sat_outbounds: list[dict] = []
        for ob in (extra_outbounds or []):
            if not isinstance(ob, dict) or not ob.get("tag"):
                continue
            if ob.get("type") in ("direct", "block", "dns", "selector", "urltest"):
                continue
            sat_outbounds.append(ob)
            extra_tags.append(ob["tag"])

        node_tags = [nd["name"] for nd in nodes]
        exit_tags = [nd["name"] for nd in reg["exits"]] or node_tags
        first_tag = node_tags[0]

        # ── Группы (selector + urltest) ─────────────────────────────────
        # Главный selector — выбор ноды + auto + сателлиты.
        selector_proxy = {
            "type": "selector",
            "tag": SELECTOR_TAG,
            "outbounds": node_tags + extra_tags + [URLTEST_TAG],
            "default": first_tag,
            "interrupt_exist_connections": True,
        }
        # urltest — авто-выбор по пингу (5 мин, tolerance 50ms).
        urltest_auto = {
            "type": "urltest",
            "tag": URLTEST_TAG,
            "outbounds": list(node_tags),
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m",
            "tolerance": 50,
            "idle_timeout": "30m",
        }

        # Streaming / Telegram / AI — каждая как selector с urltest «-auto».
        # Только если есть exit-ноды (иначе группы пустые — нет смысла).
        group_outbounds: list[dict] = []
        if exit_tags:
            for gname, gtag in (("🎬 Streaming", STREAMING_TAG),
                                ("✈️ Telegram",  TELEGRAM_TAG),
                                ("🤖 AI",         AI_TAG)):
                auto_tag = gname + " (auto)"
                # selector: первая exit-нода по умолчанию + auto + все exit.
                group_outbounds.append({
                    "type": "selector",
                    "tag": gtag,
                    "outbounds": [exit_tags[0], auto_tag] + exit_tags[1:] + [SELECTOR_TAG],
                    "default": exit_tags[0],
                })
                # urltest для этой группы (только exit-ноды).
                group_outbounds.append({
                    "type": "urltest",
                    "tag": auto_tag,
                    "outbounds": list(exit_tags),
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": "5m",
                    "tolerance": 80,
                    "idle_timeout": "30m",
                })

        # ── Защита прокси-доменов ───────────────────────────────────────
        # Нельзя пускать домены нод через прокси — иначе селектор для них
        # сам себя вызывает (бесконечный цикл до таймаута).
        node_domains = _node_domains(nodes)
        protect_rules: list[dict] = []
        if node_domains:
            protect_rules.append({
                "domain_suffix": node_domains,
                "action": "route",
                "outbound": DIRECT_TAG,
            })

        # ── Сборка route.rules ──────────────────────────────────────────
        all_rules = []
        # 1. DNS hijack — первым
        all_rules.append({"protocol": "dns", "action": "hijack-dns"})
        # 2. Adblock (rule-set → reject)
        all_rules.append({"rule_set": "geosite-category-ads-all",
                          "action": "reject"})
        # 3. Защита прокси-доменов
        all_rules.extend(protect_rules)
        # 4. Streaming/Telegram/AI — только если есть exit-ноды
        if exit_tags:
            all_rules.extend([
                {"rule_set": ["geosite-youtube", "geosite-netflix",
                              "geosite-twitch", "geosite-disney",
                              "geosite-spotify", "geosite-tiktok"],
                 "action": "route", "outbound": STREAMING_TAG},
                {"rule_set": ["geosite-telegram", "geoip-telegram"],
                 "action": "route", "outbound": TELEGRAM_TAG},
                {"rule_set": "geosite-openai",
                 "action": "route", "outbound": AI_TAG},
            ])
        # 5. РФ-домены → direct
        all_rules.append({"rule_set": "geosite-ru",
                          "action": "route", "outbound": DIRECT_TAG})
        # 6. РФ IP → direct
        all_rules.append({"rule_set": "geoip-ru",
                          "action": "route", "outbound": DIRECT_TAG})
        # 7. Private/LAN IP → direct
        all_rules.append({"rule_set": "geoip-private",
                          "action": "route", "outbound": DIRECT_TAG})

        # ── Сборка финального конфига ────────────────────────────────────
        config = {
            "log": {
                "level": "warn",
                "timestamp": True,
            },
            "dns": {
                "servers": [
                    {
                        "type": "https",
                        "tag": "remote-dns",
                        "server": "1.1.1.1",
                        "detour": SELECTOR_TAG,
                    },
                    {
                        "type": "udp",
                        "tag": "local-dns",
                        "server": "223.5.5.5",
                        "detour": DIRECT_TAG,
                    },
                    {
                        "type": "fakeip",
                        "tag": "fakeip-dns",
                    },
                ],
                "rules": [
                    # Запросы от самого sing-box (для установки соединений
                    # с proxy-серверами) — на реальный DNS, не на fakeip.
                    {"outbound": ["any"], "server": "local-dns"},
                    # Все A/AAAA → fakeip
                    {"query_type": ["A", "AAAA"], "server": "fakeip-dns"},
                ],
                "final": "remote-dns",
                "strategy": "prefer_ipv4",
                "fakeip": {
                    "enabled": True,
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18",
                },
            },
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
                    "mtu": 9000,
                    "auto_route": True,
                    "strict_route": True,
                    "stack": "system",
                },
            ],
            "outbounds": (
                [selector_proxy, urltest_auto]
                + group_outbounds
                + node_outbounds
                + sat_outbounds
                + [
                    {"type": "direct", "tag": DIRECT_TAG},
                    {"type": "block", "tag": BLOCK_TAG},
                    {"type": "dns", "tag": DNS_OUT_TAG},
                ]
            ),
            "route": {
                "rule_set": _singbox_ruleset_definitions(),
                "rules": all_rules,
                "final": SELECTOR_TAG,
                "auto_detect_interface": True,
            },
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "default_mode": "rule",
                },
                "cache_file": {
                    "enabled": True,
                    "store_fakeip": True,
                },
            },
        }

        return json.dumps(config, indent=2, ensure_ascii=False)
    except Exception as e:
        _log("ERROR", f"build_singbox_config: {e}")
        return ""

# ══════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ (пункт 8 в do_subscription_menu → управление фичей)
# ══════════════════════════════════════════════════════════════════════════

def set_multinode_enabled(mode: str) -> None:
    """mode: 'on' | 'off' | 'auto' (auto = удалить явный ключ)."""
    cfg = _load_sub_conf()
    if mode == "auto":
        cfg.get("multinode", {}).pop("enabled", None)
        if cfg.get("multinode") == {}:
            cfg.pop("multinode", None)
    else:
        cfg.setdefault("multinode", {})["enabled"] = (mode == "on")
    _save_sub_conf(cfg)


def summarize_nodes(user: Optional[dict] = None) -> list[dict]:
    """Краткий список нод для меню/панелей: [{name, kind, host, port}]."""
    reg = collect_nodes(user or {})
    return [{"name": n["name"], "kind": n["kind"],
             "host": n["host"], "port": n["port"]} for n in reg["all"]]


if __name__ == "__main__":  # pragma: no cover
    import os
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}")
        sys.exit(1)
    st = multinode_status()
    print(f"multinode: {'включена' if st['enabled'] else 'выключена'} ({st['reason']})")
    for n in summarize_nodes():
        print(f"  {n['kind']:<8} {n['name']}  →  {n['host']}:{n['port']}")
