"""
chimera/modules/chain_relay.py
───────────────────────────────────────────────────────────────────────────────
Chain Relay (релейные хопы / многохоповый каскад) — расширение Режима B.

ПРОБЛЕМА
────────
Exit-нода может быть недостижима с entry напрямую: ТСПУ дропает TCP к её
IP на транзитном пути entry (при этом сама нода жива и доступна с других
хостов). Живой кейс (окт. 2026, прод-каскад, обезличено): exit-нода —
с двух других entry VLESS работает, с третьего TCP к её IP дропается
ЦЕЛИКОМ (tcpdump: 0 SYN ни на один порт при живом ICMP). Смена порта
бесполезна.

РЕШЕНИЕ
───────
Xray-core имеет нативный механизм sockopt.dialerProxy: исходящее
соединение к exit устанавливается ЧЕРЕЗ другой outbound («хоп»).
Для хопа entry — обычный VLESS-клиент: на хопе ничего ставить не нужно,
используется его существующий инбаунд (zero-touch).

Схема: клиент → entry → [hop-1 → … → hop-N →] exit → интернет
        (цепочки произвольной глубины: хоп может иметь свой via)

STATE (state.json)
──────────────────
  relay_hops: [
    {
      "tag":     "hop-a",                # уникальный тег = tag outbound-а
      "host":    "hop1.example.com",
      "port":    443,
      "uuid":    "…",                     # клиентский UUID на хопе
      "pubkey":  "…",                     # REALITY public key хопа
      "shortid": "…",
      "sni":     "hop1.example.com",
      "fp":      "firefox",
      "flow":    "xtls-rprx-vision",
      "proto":   "reality",               # reality | xhttp | xhttp_reality
      "path":    "/",                     # для xhttp-протоколов
      "xhttp_mode": "stream-up",
      "via":     "",                      # свой хоп (N-hop, рекурсия)
      "comment": "вход через посредника FI",
      "enabled": True,
    }, …
  ]
  chain_nodes[i].via = "hop-a"           # exit через какой хоп ("" = напрямую)

ИНТЕГРАЦИЯ
──────────
  • chain_nodes.generate_xray_config_chain_entry_multi():
      - exit-нода с via → streamSettings.sockopt.dialerProxy = <tag хопа>
      - перед exit-outbound-ами добавляются hop-outbound-ы
      - без хопов конфиг БАЙТ-В-БАЙТ как раньше (обратная совместимость)
  • chain_nodes.do_manage_nodes(): пункт [H] — это меню
  • node_health_monitor.check_nodes_once(): для нод с via — full-path
    проверка (прямой TCP к такой ноде перерезан — это НЕ признак отказа)
  • diagnostics._diag_check_routing_live(): via-ноды проверяются full-path

Публичный API:
    load_relay_hops() -> list[dict]           — хопи из state.json
    save_relay_hops(hops) -> bool             — записать хопи в state.json
    validate_hops(hops) -> list[str]          — ошибки (дубли/циклы/ссылки)
    hop_via_tag_for(nd, hops) -> str | None   — тег хопа для exit-ноды
    hop_chain(tag, hops) -> list[dict]        — цепочка хопов (внешний→внутренний)
    collect_hop_outbounds(nodes, hops)        — hop-outbound-ы для конфига
    build_hop_outbound(hop) -> dict           — один hop-outbound (3 протокола)
    check_hop_tcp(hop) -> tuple[bool, float]  — TCP-проверка хопа
    check_via_node_full_path(nd, hops) -> dict— full-path проверка цепочки
        (probe-ladder http→https→IP + deep-диагностика ног; поля ответа:
         ok/ms/exit_ip/speed_mbps/detail/reason/legs/xray_tail)
    do_chain_relay_menu()                     — интерактивное меню (E → H)

Живой PoC (окт. 2026, прод-ноды, обезличено): entry → hop-a → exit и
entry → hop-b → exit — оба PASS, exit-IP подтверждён, тёплые 0.4–0.6 с.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

# Ключ в state.json со списком хопов
HOPS_STATE_KEY = "relay_hops"

# Теги, которые хоп занимать не может (заняты ядром каскада/Химеры)
RESERVED_TAGS = {
    "direct", "direct-local", "BLOCK", "chain-balancer",
    "proxy", "dns-out", "socks-in", "socks-check", "exit-check",
}

# Допустимый charset тега хопа
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Ленивый import chimera._core (как в chain_nodes.py)."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  STATE: загрузка / сохранение хопов
# =============================================================================
def load_relay_hops() -> list[dict]:
    """Читает relay_hops из state.json. Пустой список при отсутствии."""
    core = _core_module()
    state_file = getattr(core, "STATE_FILE", None)
    if not state_file or not Path(state_file).exists():
        return []
    try:
        state = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:
        return []
    hops = state.get(HOPS_STATE_KEY, [])
    if not isinstance(hops, list):
        return []
    return [h for h in hops if isinstance(h, dict)]


def save_relay_hops(hops: list[dict]) -> bool:
    """Записывает relay_hops в state.json, не трогая остальные поля.

    Возвращает True при успехе. state.json должен существовать
    (создаётся установкой) — иначе False.
    """
    core = _core_module()
    warn = core.warn
    state_file = getattr(core, "STATE_FILE", None)
    if not state_file or not Path(state_file).exists():
        warn("state.json не найден — сначала выполните установку (пункт 1).")
        return False
    try:
        state = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:
        state = {}
    state[HOPS_STATE_KEY] = hops
    try:
        Path(state_file).write_text(
            json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception as e:
        warn(f"Не удалось записать state.json: {e}")
        return False


def _chain_nodes_from_state() -> list[dict]:
    """chain_nodes из state.json (прямо, без core-глобалей)."""
    core = _core_module()
    state_file = getattr(core, "STATE_FILE", None)
    if not state_file or not Path(state_file).exists():
        return []
    try:
        state = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:
        return []
    nodes = state.get("chain_nodes", [])
    return [n for n in nodes if isinstance(n, dict)] if isinstance(nodes, list) else []


def _save_chain_nodes_via(nodes: list[dict]) -> bool:
    """Сохраняет обновлённый chain_nodes в state.json + синхронизирует core."""
    core = _core_module()
    warn = core.warn
    state_file = getattr(core, "STATE_FILE", None)
    if not state_file or not Path(state_file).exists():
        warn("state.json не найден — сначала выполните установку (пункт 1).")
        return False
    try:
        state = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:
        state = {}
    state["chain_nodes"] = nodes
    try:
        Path(state_file).write_text(
            json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        setattr(core, "CHAIN_NODES", nodes)
        return True
    except Exception as e:
        warn(f"Не удалось записать state.json: {e}")
        return False


# =============================================================================
#  Валидация
# =============================================================================
def validate_hops(hops: list[dict]) -> list[str]:
    """Проверяет набор хопов. Возвращает список ошибок (пустой = ОК).

    Проверки: уникальность/charset тега, reserved-теги, обязательные поля,
    корректность proto, ссылки via (на существующий тег), циклы и self-via.
    """
    errors: list[str] = []
    tags = [h.get("tag", "") for h in hops]

    for i, h in enumerate(hops):
        n = i + 1
        tag = h.get("tag", "")
        if not tag:
            errors.append(f"Хоп #{n}: пустой tag")
        elif not _TAG_RE.match(tag):
            errors.append(f"Хоп «{tag}»: недопустимый tag (нужен [a-zA-Z0-9_-], ≤32)")
        elif tag in RESERVED_TAGS:
            errors.append(f"Хоп «{tag}»: tag зарезервирован ядром")
        elif tags.count(tag) > 1:
            errors.append(f"Хоп «{tag}»: дублирующийся tag")

        host = h.get("host", "")
        if not host:
            errors.append(f"Хоп «{tag or f'#{n}'}»: пустой host")
        try:
            port = int(h.get("port", 0))
            if not (1 <= port <= 65535):
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"Хоп «{tag or f'#{n}'}»: некорректный port")

        uuid_ = h.get("uuid", "")
        if not re.match(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            str(uuid_)):
            errors.append(f"Хоп «{tag or f'#{n}'}»: некорректный UUID")

        proto = h.get("proto", "reality")
        if proto not in ("reality", "xhttp", "xhttp_reality"):
            errors.append(f"Хоп «{tag or f'#{n}'}»: неизвестный proto «{proto}»")

        if proto in ("reality", "xhttp_reality"):
            for fld, lbl in (("pubkey", "REALITY public key (pbk)"),
                             ("shortid", "REALITY shortId (sid)"),
                             ("sni", "SNI/serverName")):
                if not h.get(fld, ""):
                    errors.append(f"Хоп «{tag or f'#{n}'}» ({proto}): пустой {lbl}")

    # via: ссылки и циклы
    tag_set = {t for t in tags if t}
    for h in hops:
        tag = h.get("tag", "")
        via = h.get("via", "") or ""
        if not via:
            continue
        if via not in tag_set:
            errors.append(f"Хоп «{tag}»: via «{via}» не существует")
        elif via == tag:
            errors.append(f"Хоп «{tag}»: via указывает на себя (цикл)")
        else:
            # обход цепочки — цикл длины >1
            seen = {tag}
            cur = via
            while cur:
                if cur in seen:
                    errors.append(f"Хоп «{tag}»: цикл в цепочке via (…→ {cur})")
                    break
                seen.add(cur)
                nxt = next((x for x in hops if x.get("tag") == cur), None)
                cur = (nxt.get("via", "") or "") if nxt else ""
    return errors


def validate_via_for_nodes(nodes: list[dict], hops: list[dict]) -> list[str]:
    """Проверяет via у chain_nodes (ссылки на существующие хопи)."""
    tag_set = {h.get("tag", "") for h in hops}
    errors = []
    for i, nd in enumerate(nodes):
        via = nd.get("via", "") or ""
        if via and via not in tag_set:
            errors.append(
                f"Exit-нода #{i+1} ({nd.get('host', '?')}): "
                f"via «{via}» не существует в relay_hops")
    return errors


# =============================================================================
#  Разрешение via → цепочка хопов
# =============================================================================
def hop_via_tag_for(nd: dict, hops: list[dict]) -> Optional[str]:
    """Тег активного хопа для exit-ноды (None = напрямую/хоп недоступен)."""
    via = (nd or {}).get("via", "") or ""
    if not via:
        return None
    hop = next((h for h in hops if h.get("tag") == via), None)
    if not hop or not hop.get("enabled", True):
        return None
    return via


def hop_chain(tag: str, hops: list[dict]) -> list[dict]:
    """Цепочка хопов от tag вниз по via (внешний → внутренний).

    Возвращает [] если tag не найден или обнаружен цикл.
    """
    by_tag = {h.get("tag", ""): h for h in hops}
    chain: list[dict] = []
    seen = set()
    cur = tag
    while cur:
        if cur in seen:
            return []          # цикл — цепочка невалидна
        seen.add(cur)
        h = by_tag.get(cur)
        if not h:
            return []          # битая ссылка
        if not h.get("enabled", True):
            return []          # выключенный хоп разрывает цепочку
        chain.append(h)
        cur = h.get("via", "") or ""
    return chain


def _slug_tag(host: str, hops: list[dict]) -> str:
    """Генерирует уникальный tag «hop-<slug(host)>» (+ суффикс при коллизии)."""
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", host or "hop").strip("-").lower()[:20]
    base = f"hop-{slug}" if slug else "hop"
    tag, i = base, 1
    existing = {h.get("tag", "") for h in hops}
    while tag in existing or tag in RESERVED_TAGS:
        i += 1
        tag = f"{base}-{i}"
    return tag


# =============================================================================
#  Построение hop-outbound (совместим с exit-outbound каскада)
# =============================================================================
def build_hop_outbound(hop: dict) -> dict:
    """Xray-outbound для хопа. Формы зеркалят exit-outbound-ы каскада
    (chain_nodes.generate_xray_config_chain_entry_multi): reality/tcp,
    xhttp/tls, xhttp_reality. Тот же билдер используется full-path
    чекером — конфиг проверки = конфиг прод-каскада.

    Хоп с собственным via получает sockopt.dialerProxy (N-hop рекурсия).
    """
    core = _core_module()
    _build_sockopt = core._build_sockopt
    _build_exit_xhttp_outbound_settings = core._build_exit_xhttp_outbound_settings
    from chimera.modules.tfo_settings import tfo_sockopt

    AWG_EXIT_ENABLED = getattr(core, "AWG_EXIT_ENABLED", False)
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    XHTTP_TCP_NO_DELAY = getattr(core, "XHTTP_TCP_NO_DELAY", False)

    tag = hop.get("tag", "hop")
    proto = hop.get("proto", "reality")
    # Хоп с flow=xTLS Vision: default как у exit-нод каскада
    flow = hop.get("flow", "") or ""
    if proto == "reality" and not flow:
        flow = "xtls-rprx-vision"

    user = {"id": hop.get("uuid", ""), "encryption": "none"}
    if proto == "reality":
        user["flow"] = flow          # vision; xhttp-формы — без flow

    out = {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": hop.get("host", ""),
            "port": int(hop.get("port", 443)),
            "users": [user],
        }]},
    }

    if proto == "reality":
        # REALITY TCP (стандарт) — как reality-ветка exit-outbound
        out["streamSettings"] = {
            "network": "tcp",
            "security": "reality",
            "sockopt": {**_build_sockopt(),
                        **({"mark": AWG_FWMARK} if AWG_EXIT_ENABLED else {})},
            "realitySettings": {
                "show": False,
                "fingerprint": hop.get("fp", "chrome"),
                "serverName": hop.get("sni", ""),
                "publicKey": hop.get("pubkey", ""),
                "shortId": hop.get("shortid", ""),
                "spiderX": "/",
            },
        }
    elif proto == "xhttp":
        # xHTTP + TLS (LE-сертификат) — как xhttp-ветка exit-outbound
        out["streamSettings"] = {
            "network": "xhttp",
            "security": "tls",
            "sockopt": {**tfo_sockopt(),
                        "tcpKeepAliveInterval": 15,
                        "tcpKeepAliveIdle": 60,
                        "tcpUserTimeout": 30000,
                        "tcpCongestion": "bbr",
                        **({"tcpNoDelay": True} if XHTTP_TCP_NO_DELAY else {})},
            "tlsSettings": {
                "serverName": hop.get("sni", hop.get("host", "")),
                "fingerprint": hop.get("fp", "chrome"),
                "alpn": ["h2", "http/1.1"],
            },
            "xhttpSettings": _build_exit_xhttp_outbound_settings(hop),
        }
    else:
        # xHTTP + REALITY — как xhttp_reality-ветка exit-outbound
        out["streamSettings"] = {
            "network": "xhttp",
            "security": "reality",
            "sockopt": {**tfo_sockopt(),
                        "tcpKeepAliveInterval": 15,
                        "tcpKeepAliveIdle": 60,
                        "tcpUserTimeout": 30000,
                        "tcpCongestion": "bbr",
                        **({"tcpNoDelay": True} if XHTTP_TCP_NO_DELAY else {}),
                        **({"mark": AWG_FWMARK} if AWG_EXIT_ENABLED else {})},
            "xhttpSettings": _build_exit_xhttp_outbound_settings(hop),
            "realitySettings": {
                "show": False,
                "fingerprint": hop.get("fp", "chrome"),
                "serverName": hop.get("sni", ""),
                "publicKey": hop.get("pubkey", ""),
                "shortId": hop.get("shortid", ""),
                "spiderX": "/",
            },
        }

    # N-hop: хоп сам ходит через другой хоп
    via = hop.get("via", "") or ""
    if via:
        out["streamSettings"].setdefault("sockopt", {})["dialerProxy"] = via
    return out


def collect_hop_outbounds(nodes: list[dict], hops: list[dict]) -> list[dict]:
    """Hop-outbound-ы, нужные данному набору exit-нод (с рекурсией via).

    Только активные (enabled) хопи; порядок стабильный: по порядку
    первого упоминания exit-нодами. Пустой список, если via не используется.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for nd in nodes or []:
        via = hop_via_tag_for(nd, hops)
        if not via:
            continue
        for h in hop_chain(via, hops):
            t = h.get("tag", "")
            if t and t not in seen:
                seen.add(t)
                out.append(build_hop_outbound(h))
    return out


# =============================================================================
#  ЧЕКЕР: TCP хопа + full-path проверка цепочки
# =============================================================================
def _find_xray_bin() -> Optional[str]:
    """Поиск бинаря xray (для full-path чекера и cron HM)."""
    core = _core_module()
    candidates = [
        getattr(core, "XRAY_BIN", "") or "",
        "/usr/local/bin/xray",
        "/usr/bin/xray",
        "/opt/xray/xray",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return c
    return shutil.which("xray")


def check_hop_tcp(hop: dict, timeout: int = 5) -> tuple[bool, float]:
    """TCP-пинг до хоста хопа (DoH-резолв + connect, как HM).

    Возвращает (доступен, время_мс).
    """
    host = hop.get("host", "")
    port = int(hop.get("port", 443))
    if not host:
        return False, 0.0
    try:
        ip = None
        try:
            from chimera.modules.chain_nodes import _resolve_host_fresh
            ip = _resolve_host_fresh(host)
        except Exception:
            ip = None
        if not ip:
            ip = socket.gethostbyname(host)
        t0 = time.time()
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True, (time.time() - t0) * 1000
    except Exception:
        return False, 0.0


def build_check_client_config(nd: dict, hops: list[dict],
                              socks_port: int) -> Optional[dict]:
    """Конфиг временного xray-клиента для full-path проверки цепочки.

    Форма outbound-ов = прод-конфиг каскада (те же билдеры):
        socks-in (127.0.0.1:socks_port)
        → hop-outbound-ы (цепочка via nd['via'], рекурсивно)
        → exit-outbound «exit-check» с sockopt.dialerProxy = <via>
        → routing: socks-in → exit-check
    Возвращает None, если via не разрешается (хоп нет/выключен/цикл).
    """
    via = hop_via_tag_for(nd, hops)
    if not via:
        return None
    chain = hop_chain(via, hops)
    if not chain:
        return None

    hop_outbounds = [build_hop_outbound(h) for h in chain]
    # exit-outbound строится тем же билдером (поля ноды совместимы)
    exit_ob = build_hop_outbound({**nd, "tag": "exit-check"})
    exit_ob["streamSettings"].setdefault("sockopt", {})["dialerProxy"] = via

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-check",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": hop_outbounds + [exit_ob],
        "routing": {"rules": [
            {"type": "field",
             "inboundTag": ["socks-check"],
             "outboundTag": "exit-check"},
        ]},
    }


def _free_local_port() -> int:
    """Свободный loopback-порт для socks-инбаунда чекера."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ─────────────────────────────────────────────────────────────────────────────
#  full-path чекер v2: probe-ladder + диагностика ног
#
#  Живой кейс (окт. 2026, прод-юзер): единственная HTTP-проба
#  http://cp.cloudflare.com/generate_204 через цепочку отдавала 000 → «цепочка
#  отвечает некорректно (HTTP 000)» FAIL, при том что канал работал: exit-нода
#  (сеть с ограниченным egress) резала исходящий порт 80. Лестница проб различает
#  «цепь мертва» и «цепь жива, но endpoint/порт/DNS недоступны», а при полном
#  отказе диагностирует, КАКАЯ нога сломана (entry→хоп / хоп→нода / нода).
#
#  Второй живой кейс (окт. 2026, тот же юзер, вечер): [T] FAIL «нода не
#  отвечает» при живой цепи (шаг 5: full-path 425 мс; шаг 12: 2.1 Мбит/с;
#  ICMP exit↔хоп ок). Медленная цепь RU→хоп→exit (~400 мс RTT) не укладывалась
#  в одиночную 6-с https-пробу, а IP-фолбэки 1.1.1.1/8.8.8.8 — DoH-эндпоинты,
#  фильтруемые сетью exit. Итог: P2 с ретраем, P2b через
#  --resolve (DNS на exit не участвует) и честный вердикт ног (см.
#  _diagnose_dead_chain: «напрямую недоступна» для via-ноды — норма, ТСПУ).
# ─────────────────────────────────────────────────────────────────────────────
_PROBE_HOST      = "cp.cloudflare.com"                       # probe-домен (P1/P2/P2b)
_PROBE_HTTP_204  = f"http://{_PROBE_HOST}/generate_204"      # домен + порт 80
_PROBE_HTTPS_204 = f"https://{_PROBE_HOST}/generate_204"     # домен + порт 443
_PROBE_IP_CF     = "https://1.1.1.1/"                        # IP, без DNS (Cloudflare)
_PROBE_IP_GG     = "https://8.8.8.8/"                        # IP, без DNS (Google)


def _socks_check_inbound(socks_port: int) -> dict:
    """Socks-инбаунд временного xray-клиента чекера."""
    return {
        "tag": "socks-check",
        "listen": "127.0.0.1",
        "port": socks_port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }


def _curl_socks(socks_port: int, url: str, timeout: int,
                insecure: bool = False,
                resolve: Optional[str] = None) -> tuple[int, str, Optional[float]]:
    """curl через socks5h → (rc, http_code, ms). '000'/'' — HTTP-ответа нет.

    rc=7 — не поднялся сам socks (xray ещё стартует); 28 — таймаут на цепи.
    resolve — «host:port:ip» для curl --resolve: endpoint тот же (SNI/Host
    честные), но DNS на exit не участвует — IP резолвится на entry (P2b).
    """
    cmd = ["curl", "-s", "-o", "/dev/null",
           "-w", "%{http_code} %{time_total}",
           "-m", str(timeout),
           "-x", f"socks5h://127.0.0.1:{socks_port}"]
    if insecure:
        cmd.append("-k")
    if resolve:
        cmd += ["--resolve", resolve]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return 28, "000", None
    parts = (r.stdout or "").split()
    code = parts[0] if parts else ""
    ms: Optional[float] = None
    if len(parts) > 1:
        try:
            ms = float(parts[1]) * 1000
        except ValueError:
            pass
    return r.returncode, code, ms


class _TempXrayClient:
    """Временный xray-клиент (контекст-менеджер).

    Отличия от старого инлайн-запуска в check_via_node_full_path:
      • stderr пишется в ФАЙЛ, а не в PIPE — пайп без дренажа мог
        переполниться (64 КБ) и заблокировать xray посреди проверки;
        заодно хвост ошибок доступен для диагностики (err_tail);
      • готовность определяется ретраями curl по rc=7 (см. _probe_ladder),
        а не сном time.sleep(1.5): на медленном VPS xray мог не успеть
        подняться за 1.5 с → ложный «HTTP 000».
    """

    def __init__(self, cfg: dict, xbin: str):
        self.cfg = cfg
        self.xbin = xbin
        self.proc = None
        self.cfg_path: Optional[str] = None
        self.err_path: Optional[str] = None
        self.start_error = ""

    def __enter__(self) -> "_TempXrayClient":
        import os as _os
        fd, self.cfg_path = tempfile.mkstemp(prefix="relaycheck_", suffix=".json")
        _os.write(fd, json.dumps(self.cfg, indent=2,
                                 ensure_ascii=False).encode("utf-8"))
        _os.close(fd)
        self.err_path = self.cfg_path + ".err"
        err_fh = open(self.err_path, "w+b")
        try:
            self.proc = subprocess.Popen(
                [self.xbin, "run", "-c", self.cfg_path],
                stdout=subprocess.DEVNULL, stderr=err_fh)
        except Exception as e:
            self.start_error = f"xray не стартовал: {e}"
        finally:
            err_fh.close()
        return self

    def alive(self) -> bool:
        """xray жив (не упал на старте)."""
        return self.proc is not None and self.proc.poll() is None

    def err_tail(self, limit: int = 240) -> str:
        """Хвост stderr xray (последние строки) — для диагностики отказа."""
        try:
            txt = Path(self.err_path).read_text(encoding="utf-8",
                                                errors="replace")
        except Exception:
            return ""
        lines = [ln.strip() for ln in txt.strip().splitlines() if ln.strip()]
        return (" | ".join(lines[-2:]))[-limit:] if lines else ""

    def __exit__(self, *exc) -> bool:
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        for p in (self.cfg_path, self.err_path):
            if p:
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass
        return False


def _resolve_probe_host_ipv4(host: str = _PROBE_HOST) -> Optional[str]:
    """IPv4 probe-хоста, резолв НА СТОРОНЕ ENTRY (не через цепочку).

    Для P2b: endpoint тот же, что у P2, но DNS на exit не участвует
    (--resolve). Покрывает медленный/сломанный DNS на exit и сети, где
    DoH-IP (1.1.1.1/8.8.8.8) фильтруются (живой кейс окт. 2026:
    сеть с ограниченным egress). Вызывается ТОЛЬКО после неудачи P1+P2,
    на живом пути не тратит ни одного запроса. Любая ошибка → None
    (шаг P2b просто пропускается).
    """
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET,
                                   socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except Exception:
        return None


def _probe_ladder(socks_port: int, t_domain: int, t_fast: int = 8,
                  t_ip: int = 6, retry_startup: float = 8.0) -> dict:
    """Лестница HTTP-проб через socks-цепочку (различает отказы).

    P1  http  generate_204 — порт 80 + DNS на exit (с ретраями rc=7,
          пока xray не поднялся — вместо слепого sleep);
    P2  https generate_204 — порт 443 + DNS (exit может резать 80-й);
          ДВЕ попытки (вторая щедрее по таймауту): медленная цепь
          (живой кейс окт. 2026: ~400 мс RTT) не должна
          валиться одиночной пробой;
    P2b https generate_204 c --resolve на IP, резолвленный на ENTRY:
          DNS на exit не участвует, SNI честный — покрывает медленный/
          сломанный DNS на exit и фильтрацию DoH-IP на сети exit;
    P3/P4 https IP-literal — 443 без DNS (1.1.1.1 / 8.8.8.8).

    Любой HTTP-код ≠ 000 = цепь ДОСТАВЛЯЕТ трафик. Возвращает:
      delivered      — есть хоть какой-то HTTP-ответ
      domain_ok      — ответила доменная проба (P1/P2) → цепь + DNS живы
      code / ms      — код и латентность успешной пробы
      port80_blocked — P1 молчит, P2 отвечает (80-й режется на exit)
      ip_only        — доменные пробы молчат, IP-проба отвечает (DNS на exit)
    """
    res = {"delivered": False, "domain_ok": False, "code": "", "ms": None,
           "port80_blocked": False, "ip_only": False}

    # P1: http 204 (порт 80 + DNS), с ожиданием старта socks
    deadline = time.time() + retry_startup
    while True:
        rc, code, ms = _curl_socks(socks_port, _PROBE_HTTP_204, t_domain)
        if code and code != "000":
            res.update(delivered=True, domain_ok=True, code=code, ms=ms)
            return res
        if rc == 7 and time.time() < deadline:
            time.sleep(0.4)          # socks ещё не поднялся — xray стартует
            continue
        break

    # P2: https 204 (порт 443 + DNS), 2 попытки — джиттер/медленная цепь
    # не должны валить основную доменную пробу (вторая попытка щедрее)
    for _t in (t_fast, max(t_fast, 10)):
        rc, code, ms = _curl_socks(socks_port, _PROBE_HTTPS_204, _t)
        if code and code != "000":
            res.update(delivered=True, domain_ok=True, code=code, ms=ms,
                       port80_blocked=True)
            return res

    # P2b: тот же endpoint, но IP резолвим на ENTRY (--resolve): DNS на
    # exit не участвует. Живой кейс окт. 2026: exit-сеть с ограниченным egress
    # фильтрует DoH-IP (1.1.1.1/8.8.8.8) — P3/P4 молчат при живой цепи.
    _cf_ip = _resolve_probe_host_ipv4()
    if _cf_ip:
        rc, code, ms = _curl_socks(socks_port, _PROBE_HTTPS_204, t_ip,
                                    resolve=f"{_PROBE_HOST}:443:{_cf_ip}")
        if code and code != "000":
            res.update(delivered=True, code=code, ms=ms, ip_only=True)
            return res

    # P3/P4: https на IP-literal (-k): без DNS, не только Cloudflare
    for url in (_PROBE_IP_CF, _PROBE_IP_GG):
        rc, code, ms = _curl_socks(socks_port, url, t_ip, insecure=True)
        if code and code != "000":
            res.update(delivered=True, code=code, ms=ms, ip_only=True)
            return res
    return res


def _diagnose_dead_chain(nd: dict, chain: list[dict], xbin: str,
                         curl_timeout: int) -> dict:
    """Все пробы молчат → определяем, КАКАЯ нога цепочки сломана.

    Поднимает два коротких временных xray-клиента:
      1) только хопы (entry → hop-1 → … → интернет) — жива ли нога до хопа
         (REALITY-хендшейк с хопом, а не только TCP-пинг);
      2) только нода БЕЗ dialerProxy (entry → exit напрямую).
    По сочетанию результатов — диагноз и подсказка, что проверять.
    """
    legs = {"hop": "skip", "direct": "skip"}
    hop = chain[0]
    fast = max(4, min(8, curl_timeout))

    # 1) нога entry → хоп(ы) → интернет
    socks1 = _free_local_port()
    cfg1 = {
        "log": {"loglevel": "warning"},
        "inbounds": [_socks_check_inbound(socks1)],
        "outbounds": [build_hop_outbound(h) for h in chain],
        "routing": {"rules": [{
            "type": "field", "inboundTag": ["socks-check"],
            "outboundTag": hop.get("tag", "hop"),
        }]},
    }
    with _TempXrayClient(cfg1, xbin) as c1:
        if c1.start_error or not c1.alive():
            legs["hop"] = "fail"
        else:
            p1 = _probe_ladder(socks1, fast, t_fast=fast, t_ip=fast,
                               retry_startup=4.0)
            legs["hop"] = "ok" if p1["delivered"] else "fail"

    # 2) нода напрямую (без хопа)
    socks2 = _free_local_port()
    exit_ob = build_hop_outbound({**nd, "tag": "exit-check", "via": ""})
    cfg2 = {
        "log": {"loglevel": "warning"},
        "inbounds": [_socks_check_inbound(socks2)],
        "outbounds": [exit_ob],
        "routing": {"rules": [{
            "type": "field", "inboundTag": ["socks-check"],
            "outboundTag": "exit-check",
        }]},
    }
    with _TempXrayClient(cfg2, xbin) as c2:
        if c2.start_error or not c2.alive():
            legs["direct"] = "fail"
        else:
            p2 = _probe_ladder(socks2, fast, t_fast=fast, t_ip=fast,
                               retry_startup=4.0)
            legs["direct"] = "ok" if p2["delivered"] else "fail"

    hp = f"{hop.get('host', '?')}:{hop.get('port', '?')}"
    xp = f"{nd.get('host', '?')}:{nd.get('port', '?')}"
    hop_tag = hop.get("tag", "hop")
    if legs["hop"] == "fail" and legs["direct"] == "ok":
        reason = "хоп не отвечает"
        detail = (f"хоп «{hop_tag}» ({hp}): TCP до него есть, но VLESS через "
                  f"него не устанавливается — проверьте uuid/pbk/sid/sni/flow "
                  f"хопа (или хоп-сервер жив?)")
    elif legs["hop"] == "ok" and legs["direct"] == "ok":
        reason = "хоп→нода недостижима"
        detail = (f"хоп «{hop_tag}» жив, нода {xp} напрямую жива, но с хопа до "
                  f"ноды не достучаться — проверьте на ноде файервол/порт и "
                  f"доступность {xp} с хопа")
    elif legs["hop"] == "ok" and legs["direct"] == "fail":
        # Живой кейс (окт. 2026, вечер): вердикт «нода не отвечает»
        # противоречил ICMP exit↔хоп и полному тесту (шаг 5/12 ОК).
        # Прямая недоступность для via-ноды — НОРМА (ТСПУ, ради этого
        # хоп и поставлен), а «через хоп не идёт» мерялось одиночными
        # короткими пробами на медленной цепи. Говорим честно: не
        # отвечает именно нога хоп→нода (или цепь была перегружена).
        reason = "хоп→нода не доставляет"
        detail = (f"нога хоп→нода: ни одна проба не прошла (хоп жив; напрямую "
                  f"нода недоступна — норма для via-ноды, путь режет ТСПУ, это "
                  f"не признак смерти ноды). Если полный тест (шаг 5/12) "
                  f"проходит — цепочка была медленной/перегруженной в момент "
                  f"пробы, повторите [T]; иначе проверьте с хопа nc -zv "
                  f"{nd.get('host', '?')} {nd.get('port', '?')}, ключи ноды "
                  f"(uuid/pbk/sid/sni) и xray на ней")
    else:
        reason = "хоп и нода не отвечают"
        detail = (f"не отвечают ни хоп «{hop_tag}» ({hp}), ни нода {xp} по "
                  f"VLESS — проверьте ключи/серверы обоих")
    return {"legs": legs, "reason": reason, "detail": detail}


def check_via_node_full_path(nd: dict, hops: list[dict],
                             want_ip: bool = False,
                             curl_timeout: int = 20,
                             want_speed_mb: int = 0,
                             deep_diag: bool = True) -> dict:
    """Full-path проверка exit-ноды с via: временный xray-клиент + curl.

    Поднимается отдельный xray (socks 127.0.0.1:<free port>) с цепочкой
    hop-1 → … → hop-N → exit (dialerProxy), через него гоняется ЛЕСТНИЦА
    проб (_probe_ladder): http 204 → https 204 → https на IP-literal.
    Это проверяет РЕАЛЬНУЮ работоспособность цепочки (REALITY-хендшейки
    обеих ног + маршрутизацию), а не только TCP-доступность — прямой TCP
    к via-ноде может быть перерезан ТСПУ и не является признаком отказа.

    Лестница различает отказы (живой кейс окт. 2026 №1: exit резал порт 80 →
    старая одиночная http-проба вечно FAIL при живой цепи; кейс №2: медленная
    цепь с ~400 мс RTT — одиночная 6-с https-проба таймаутила, а DoH-IP
    1.1.1.1/8.8.8.8 фильтровались сетью exit → ложный «нода не отвечает»
    при живой цепи; теперь P2 с ретраем + P2b через --resolve):
      • http 204 → цепь жива;
      • https 204 (http молчит; 2 попытки) → цепь жива, exit режет порт 80;
      • только IP-проба (P2b/P3/P4) проходит → цепь доходит, но DNS/domains
        на exit сломаны → ok=False с диагнозом;
      • всё молчит → ok=False; при deep_diag=True дополнительно
        поднимаются два мини-клиента (только хоп / только нода напрямую)
        и определяется, КАКАЯ нога сломана (см. _diagnose_dead_chain).

    want_speed_mb > 0 — дополнительно качает want_speed_mb МБ с Cloudflare
    SpeedTest ЧЕРЕЗ цепочку и возвращает поле speed_mbps (реальная скорость
    полного пути, а не прямого канала entry-сервера).

    deep_diag=False — не запускать диагностику ног при отказе (для частых
    фоновых вызовов HM/балансера: их интересует только ok/не-ok).

    Возвращает dict:
        ok          — цепочка жива (доменная проба доставила ответ)
        ms          — латентность полного пути (time_total curl)
        exit_ip     — внешний IP (только при want_ip=True и ok)
        speed_mbps  — Мбит/с через цепочку (только при want_speed_mb>0 и ok)
        detail      — человекочитаемое описание (для HM-лога/меню)
        reason      — короткая причина отказа (для однострочного вывода)
        legs        — {'hop': ok|fail|skip, 'direct': ok|fail|skip}
                      (диагностика ног, только при deep_diag и отказе)
        xray_tail   — хвост stderr xray-чекера (при отказе)
    """
    res = {"ok": False, "ms": 0.0, "exit_ip": "", "speed_mbps": 0.0,
           "detail": "", "reason": "", "legs": {}, "xray_tail": ""}
    via = hop_via_tag_for(nd, hops)
    if not via:
        res["detail"] = (f"via «{(nd or {}).get('via', '')}» не найден/выключен"
                         if (nd or {}).get("via") else "via не задан")
        res["reason"] = "via не задан"
        return res
    chain = hop_chain(via, hops)
    if not chain:
        res["detail"] = f"цепочка via «{via}» битая (цикл/битая ссылка)"
        res["reason"] = "битая via"
        return res

    xbin = _find_xray_bin()
    if not xbin:
        res["detail"] = "xray-бинарь не найден для full-path проверки"
        res["reason"] = "нет xray"
        return res

    socks_port = _free_local_port()
    cfg = build_check_client_config(nd, hops, socks_port)
    if cfg is None:
        res["detail"] = "не удалось собрать конфиг проверки"
        res["reason"] = "конфиг не собрался"
        return res

    try:
        with _TempXrayClient(cfg, xbin) as client:
            if client.start_error:
                res["detail"] = client.start_error
                res["reason"] = "xray не стартовал"
                return res
            if not client.alive():
                err = client.err_tail(200)
                res["detail"] = f"xray чекера упал: {err or '?'}"
                res["reason"] = "xray упал"
                return res

            # 1) liveness: лестница проб через цепочку
            pr = _probe_ladder(socks_port, curl_timeout)
            hops_lbl = " → ".join([h.get("tag", "?") for h in chain])
            if pr["domain_ok"]:
                res["ok"] = True
                res["ms"] = pr["ms"] or 0.0
                res["reason"] = "цепь жива"
                note = ""
                if pr["port80_blocked"]:
                    note = " — порт 80 с exit режется, 443 ок"
                elif pr["code"] != "204":
                    note = f" — проба отдала HTTP {pr['code']}, не 204"
                res["detail"] = f"цепочка жива ({hops_lbl} → exit){note}"
            elif pr["delivered"]:
                # IP-проба проходит, доменные — нет: цепь доходит, но
                # DNS/домены на exit-ноде не работают → реальный трафик
                # (клиенты шлют домены) через такую ноду не пойдёт.
                res["reason"] = "DNS на exit"
                res["detail"] = ("цепь доходит (IP-проба проходит), но домены "
                                 "с ноды не резолвятся — проверьте DNS/порт 53 "
                                 "на exit-ноде")
            else:
                # полный отказ: все пробы без ответа
                res["xray_tail"] = client.err_tail()
                if deep_diag:
                    _d = _diagnose_dead_chain(nd, chain, xbin, curl_timeout)
                    res["legs"] = _d["legs"]
                    res["reason"] = _d["reason"]
                    res["detail"] = _d["detail"]
                else:
                    res["reason"] = "цепь не отвечает"
                    res["detail"] = "цепочка не отвечает (все HTTP-пробы 000)"
                if res["xray_tail"]:
                    res["detail"] += f"  |  xray: {res['xray_tail'][-120:]}"
            if not res["ok"]:
                return res

            # 2) exit-IP (опционально, для меню)
            if want_ip:
                r2 = subprocess.run(
                    ["curl", "-s", "-m", str(curl_timeout),
                     "-x", f"socks5h://127.0.0.1:{socks_port}",
                     "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=curl_timeout + 10)
                ip = (r2.stdout or "").strip()
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                    res["exit_ip"] = ip

            # 3) скорость через цепочку (опционально, для speed-test)
            if want_speed_mb > 0:
                _mb = max(1, int(want_speed_mb))
                _dl_timeout = max(60, _mb * 8)
                try:
                    from chimera.modules.chain_nodes import _resolve_host_fresh
                    _cf_ip = _resolve_host_fresh("speed.cloudflare.com")
                except Exception:
                    _cf_ip = None
                _dl = ["curl", "-s", "-o", "/dev/null", "-m", str(_dl_timeout),
                       "-w", "%{size_download} %{time_total} %{speed_download}",
                       "-x", f"socks5h://127.0.0.1:{socks_port}"]
                if _cf_ip:
                    _dl += ["--resolve", f"speed.cloudflare.com:443:{_cf_ip}"]
                _dl.append(f"https://speed.cloudflare.com/__down?bytes={_mb * 1048576}")
                r3 = subprocess.run(_dl, capture_output=True, text=True,
                                    timeout=_dl_timeout + 15)
                _p = (r3.stdout or "").split()
                if r3.returncode == 0 and len(_p) >= 3:
                    try:
                        _size_b = int(_p[0])
                        if _size_b >= 1024 * 100:      # ≥100 КБ — считаем валидным
                            res["speed_mbps"] = float(_p[2]) * 8 / 1_000_000
                    except ValueError:
                        pass

            return res

    except Exception as e:
        res["detail"] = f"ошибка full-path проверки: {type(e).__name__}: {e}"
        res["reason"] = "ошибка проверки"
        return res


# =============================================================================
#  ИНТЕРАКТИВНОЕ МЕНЮ (Режим B → E → H)
# =============================================================================
def _offer_rebuild() -> None:
    """Предложить пересборку конфига Xray после изменения хопов/via."""
    core = _core_module()
    warn = core.warn
    _rebuild = getattr(core, "_rebuild_and_restart_xray", None)
    if not callable(_rebuild):
        return
    try:
        ans = input("  Пересобрать конфиг Xray и перезапустить сейчас? [y/N]: ").strip().lower()
        if ans == "y":
            _rebuild("Xray активен — relay-хопы применены")
    except Exception:
        pass


def _hop_from_link() -> Optional[dict]:
    """Новый хоп из vless:// ссылки (парсер ядра parse_vless_link)."""
    core = _core_module()
    warn = core.warn
    try:
        link = input("  Вставьте VLESS-ссылку: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not link:
        return None
    parsed = core.parse_vless_link(link)
    if not parsed:
        warn("Не удалось распарсить ссылку.")
        return None
    return {
        "tag": "", "host": parsed["host"], "port": parsed["port"],
        "uuid": parsed["uuid"], "pubkey": parsed.get("pubkey", ""),
        "shortid": parsed.get("shortid", ""), "sni": parsed.get("sni", ""),
        "fp": parsed.get("fp", "chrome"), "flow": parsed.get("flow", ""),
        "proto": parsed.get("proto", "reality"),
        "path": parsed.get("path", "/"),
        "xhttp_mode": parsed.get("xhttp_mode", "stream-up"),
        "via": "", "comment": "", "enabled": True,
    }


def _hop_from_chain_node() -> Optional[dict]:
    """Новый хоп из существующей exit-ноды каскада (копия клиентских полей)."""
    core = _core_module()
    nodes = _chain_nodes_from_state()
    if not nodes:
        core.warn("В каскаде нет exit-нод (state.json: chain_nodes пуст).")
        return None
    print()
    for i, nd in enumerate(nodes):
        print(f"    [{i+1}] {nd.get('host', '?')}:{nd.get('port', 443)}  "
              f"proto={nd.get('proto', 'reality')}")
    try:
        ch = input("  Номер ноды (0 — отмена): ").strip()
        idx = int(ch) - 1 if ch else -1
    except ValueError:
        idx = -2
    if not (0 <= idx < len(nodes)):
        return None
    nd = nodes[idx]
    return {
        "tag": "", "host": nd.get("host", ""), "port": nd.get("port", 443),
        "uuid": nd.get("uuid", ""), "pubkey": nd.get("pubkey", ""),
        "shortid": nd.get("shortid", ""), "sni": nd.get("sni", ""),
        "fp": nd.get("fp", "chrome"), "flow": nd.get("flow", ""),
        "proto": nd.get("proto", "reality"),
        "path": nd.get("path", "/"),
        "xhttp_mode": nd.get("xhttp_mode", "stream-up"),
        "via": "", "comment": "", "enabled": True,
    }


_HOP_FIELDS = [
    # (ключ, метка, подсказка-пример)
    ("host",        "Host",                  "hop.example.net"),
    ("port",        "Port",                  "443"),
    ("uuid",        "UUID (клиентский)",     "d34df00d-1111-…"),
    ("pubkey",      "REALITY pbk",           "RkFLRS1yZWFsaXR5LXB1YmxpYy1rZXkt…"),
    ("shortid",     "REALITY sid",           "0f1e2d3c4b5a6978"),
    ("sni",         "SNI (serverName)",      "hop.example.net"),
    ("fp",          "Fingerprint",           "firefox"),
    ("flow",        "Flow",                  "xtls-rprx-vision"),
    ("proto",       "Proto (reality/xhttp/xhttp_reality)", "reality"),
    ("path",        "Path (xhttp)",          "/"),
    ("xhttp_mode",  "xhttp mode",            "stream-up"),
    ("via",         "Via (свой хоп, N-hop)", "hop-… / пусто"),
    ("comment",     "Комментарий",           "вход через посредника FI"),
]


def _hop_manual(hop: Optional[dict] = None) -> Optional[dict]:
    """Ручной ввод/редактирование полей хопа (по одному, Enter = сохранить)."""
    h = dict(hop) if hop else {}
    print(f"  {getattr(_core_module(), 'DIM', '')}"
          f"Enter — оставить текущее значение.{getattr(_core_module(), 'NC', '')}")
    for key, label, example in _HOP_FIELDS:
        cur = h.get(key, "")
        if key == "port":
            cur = str(cur or 443)
        try:
            v = input(f"  {label} [{cur or example}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if v:
            h[key] = v
        elif key not in h:
            h[key] = cur
    if h.get("proto") == "reality" and not h.get("flow"):
        h["flow"] = "xtls-rprx-vision"
    try:
        h["port"] = int(h.get("port", 443))
    except (TypeError, ValueError):
        h["port"] = 443
    h.setdefault("enabled", True)
    return h


def do_chain_relay_menu() -> None:
    """Интерактивное меню управления релейными хопами (E → H)."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_item_exit = core._box_item_exit
    _box_sep = core._box_sep
    _box_info = core._box_info
    _box_warn = core._box_warn
    _box_ok = core._box_ok
    info = core.info
    warn = core.warn
    success = core.success
    BOLD, CYAN, YELLOW, GREEN, RED, DIM, BLUE, NC = (
        core.BOLD, core.CYAN, core.YELLOW, core.GREEN, core.RED,
        core.DIM, core.BLUE, core.NC)

    import os as _os

    while True:
        _os.system("clear")
        hops = load_relay_hops()
        nodes = _chain_nodes_from_state()

        _box_top("⛓  CHAIN RELAY — РЕЛЕЙНЫЕ ХОПЫ (многохоповый каскад)")
        _box_row(f"  {DIM}Хоп = посредник: если exit недостижим напрямую (ТСПУ дроп по IP),{NC}")
        _box_row(f"  {DIM}соединение к exit устанавливается ЧЕРЕЗ хоп (Xray sockopt.dialerProxy).{NC}")
        _box_row(f"  {DIM}На самом хопе ничего ставить не нужно — entry для него обычный клиент.{NC}")
        _box_sep()

        if hops:
            _box_row(f"  {BOLD}Хопи ({len(hops)}):{NC}")
            for h in hops:
                en = (f"{GREEN}вкл{NC}" if h.get("enabled", True)
                      else f"{RED}выкл{NC}")
                via = (f"  {DIM}via:{h.get('via')}{NC}" if h.get("via") else "")
                cmt = (f"  {DIM}# {h.get('comment')}{NC}" if h.get("comment") else "")
                _box_row(f"    {CYAN}{h.get('tag', '?')}{NC}  "
                         f"{h.get('host', '?')}:{h.get('port', 443)}  "
                         f"{h.get('proto', 'reality')}  [{en}]{via}{cmt}")
        else:
            _box_row(f"  {DIM}Хопов нет.{NC}")
        _box_sep()

        if nodes:
            _box_row(f"  {BOLD}Exit-ноды → via:{NC}")
            for i, nd in enumerate(nodes):
                via = nd.get("via", "") or ""
                via_s = (f"{CYAN}{via}{NC}" if via else f"{DIM}напрямую{NC}")
                _box_row(f"    [{i+1}] {nd.get('host', '?')}:{nd.get('port', 443)}"
                         f"  →  {via_s}")
        _box_sep()

        _box_item("A", "Добавить хоп (vless-ссылка / из exit-ноды / вручную)")
        if hops:
            _box_item("E", "Изменить хоп (поля / вкл-выкл)")
            _box_item("D", "Удалить хоп")
        if nodes:
            _box_item("V", "Назначить exit-ноде хоп (via) / убрать")
        _box_item("T", "Проверить цепочки сейчас (full-path: exit-IP + латентность)")
        _box_item_exit("0", "Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if ch in ("0", "q", ""):
            break

        # ── [A] Добавить хоп ─────────────────────────────────────────────
        elif ch == "a":
            print()
            _box_item("1", "Из VLESS-ссылки")
            _box_item("2", "Из exit-ноды каскада (копия полей)")
            _box_item("3", "Вручную по полям")
            try:
                src = input("  Источник [1/2/3]: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            hop = None
            if src == "1":
                hop = _hop_from_link()
            elif src == "2":
                hop = _hop_from_chain_node()
            elif src == "3":
                hop = _hop_manual()
            else:
                continue
            if not hop:
                continue
            # tag + comment
            default_tag = _slug_tag(hop.get("host", ""), hops)
            try:
                t = input(f"  Tag хопа [{default_tag}]: ").strip()
                hop["tag"] = t or default_tag
                c = input(f"  Комментарий []: ").strip()
                if c:
                    hop["comment"] = c
            except (EOFError, KeyboardInterrupt):
                continue
            errs = validate_hops(hops + [hop])
            if errs:
                for e in errs:
                    warn(f"  ✗ {e}")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            hops.append(hop)
            if save_relay_hops(hops):
                success(f"  ✓ Хоп «{hop['tag']}» добавлен")
                _offer_rebuild()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [E] Изменить хоп ─────────────────────────────────────────────
        elif ch == "e" and hops:
            try:
                n = input("  Номер хопа (0 — отмена): ").strip()
                idx = int(n) - 1 if n else -1
            except ValueError:
                idx = -2
            if not (0 <= idx < len(hops)):
                continue
            hop = hops[idx]
            _cur = "вкл" if hop.get("enabled", True) else "выкл"
            try:
                mode = input(
                    f"  [P] поля / [T] вкл-выкл [сейчас: {_cur}] / Enter-отмена: "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if mode == "t":
                hop["enabled"] = not hop.get("enabled", True)
                if save_relay_hops(hops):
                    _st = "включён" if hop["enabled"] else "выключен"
                    success(f"  ✓ Хоп «{hop.get('tag')}» {_st}")
                    _offer_rebuild()
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            if mode != "p":
                continue
            print(f"\n  Редактирование «{hop.get('tag')}» — Enter = оставить")
            hop2 = _hop_manual(hop)
            if hop2 is None:
                continue
            hop2["tag"] = hop.get("tag")       # tag не меняем здесь
            errs = validate_hops(hops[:idx] + [hop2] + hops[idx+1:])
            if errs:
                for e in errs:
                    warn(f"  ✗ {e}")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            hops[idx] = hop2
            if save_relay_hops(hops):
                success(f"  ✓ Хоп «{hop2['tag']}» обновлён")
                _offer_rebuild()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [D] Удалить хоп ──────────────────────────────────────────────
        elif ch == "d" and hops:
            try:
                n = input("  Номер хопа (0 — отмена): ").strip()
                idx = int(n) - 1 if n else -1
            except ValueError:
                idx = -2
            if not (0 <= idx < len(hops)):
                continue
            tag = hops[idx].get("tag", "")
            # кто использует?
            used_by = [nd.get("host", "?") for nd in nodes if nd.get("via") == tag]
            used_by_hops = [h.get("tag", "?") for h in hops
                            if h.get("via") == tag and h.get("tag") != tag]
            if used_by or used_by_hops:
                warn(f"  Хоп «{tag}» используется: exit-ноды: {', '.join(used_by) or '—'};"
                     f" хопи: {', '.join(used_by_hops) or '—'}")
                warn("  Сначала снимите зависимости (V / E).")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            try:
                ok = input(f"  Удалить хоп «{tag}»? [y/N]: ").strip().lower() == "y"
            except (EOFError, KeyboardInterrupt):
                ok = False
            if ok:
                hops.pop(idx)
                if save_relay_hops(hops):
                    success(f"  ✓ Хоп «{tag}» удалён")
                    _offer_rebuild()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [V] Назначить via ────────────────────────────────────────────
        elif ch == "v" and nodes:
            try:
                n = input("  Номер exit-ноды (0 — отмена): ").strip()
                idx = int(n) - 1 if n else -1
            except ValueError:
                idx = -2
            if not (0 <= idx < len(nodes)):
                continue
            nd = nodes[idx]
            print(f"\n  Exit-нода: {nd.get('host')}:{nd.get('port')}")
            if not hops:
                warn("  Хопов нет — сначала добавьте хоп (A).")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            for j, h in enumerate(hops):
                en = "" if h.get("enabled", True) else f" {RED}[выкл]{NC}"
                print(f"    [{j+1}] {h.get('tag')}  {h.get('host')}:{h.get('port')}{en}")
            print(f"    [0] Без хопа (напрямую)")
            try:
                v = input("  Через какой хоп [номер/0]: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if v == "":
                continue
            if v == "0":
                nd["via"] = ""
            else:
                try:
                    vi = int(v) - 1
                    if not (0 <= vi < len(hops)):
                        raise ValueError
                    nd["via"] = hops[vi].get("tag", "")
                except ValueError:
                    warn("  Некорректный выбор.")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
            if _save_chain_nodes_via(nodes):
                via_lbl = nd.get("via") or "напрямую"
                success(f"  ✓ {nd.get('host')}: via = {via_lbl}")
                _offer_rebuild()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [T] Проверить цепочки ────────────────────────────────────────
        elif ch == "t":
            print()
            _box_top("⛓  ПРОВЕРКА ЦЕПОЧЕК")
            _box_row(f"  {DIM}Хопи — TCP-пинг; exit-ноды с via — full-path{NC}")
            _box_row(f"  {DIM}(временный xray-клиент через цепочку + HTTP-проба).{NC}")
            _box_sep()
            if not hops:
                _box_warn("Хопов нет — проверять нечего")
                _box_bottom()
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            for h in hops:
                ok, ms = check_hop_tcp(h)
                st = (f"{GREEN}OK {ms:.0f} мс{NC}" if ok else f"{RED}DOWN{NC}")
                _box_row(f"  hop {h.get('tag')}:  {h.get('host')}:{h.get('port')}  →  {st}")
            _box_sep()
            for nd in nodes:
                via = nd.get("via", "") or ""
                if not via:
                    ok, ms = check_hop_tcp(nd)
                    st = (f"{GREEN}OK {ms:.0f} мс{NC}" if ok else f"{RED}DOWN{NC}")
                    _box_row(f"  exit {nd.get('host')}:  (напрямую)  →  {st}")
                elif not hop_via_tag_for(nd, hops):
                    # Хоп выключен/удалён: генератор прод-конфига в этом
                    # случае подключает ноду НАПРЯМУЮ (без dialerProxy) —
                    # FAIL «via не найден» был бы ложным. Проверяем TCP,
                    # как генератор (зеркалит test_disabled_hop_falls_
                    # back_direct).
                    ok, ms = check_hop_tcp(nd)
                    st = (f"{GREEN}OK {ms:.0f} мс{NC}" if ok else f"{RED}DOWN{NC}")
                    _box_row(f"  exit {nd.get('host')}:  "
                             f"(via {via} {RED}выкл{NC} → напрямую)  →  {st}")
                else:
                    r = check_via_node_full_path(nd, hops, want_ip=True)
                    if r["ok"]:
                        st = (f"{GREEN}OK {r['ms']:.0f} мс{NC}  "
                              f"exit-IP: {BOLD}{r['exit_ip'] or '?'}{NC}")
                        _box_row(f"  exit {nd.get('host')}:  (via {via})  →  {st}")
                        # некритичные заметки (порт 80 режется и т.п.)
                        _note = r.get("detail", "")
                        if " — " in _note:
                            _box_row(f"    {DIM}↳ "
                                     f"{_note.split(' — ', 1)[1][:90]}{NC}")
                    else:
                        _box_row(f"  exit {nd.get('host')}:  (via {via})  →  "
                                 f"{RED}FAIL{NC}  {DIM}{r.get('reason', '')}{NC}")
                        if r.get("detail"):
                            _box_row(f"    {DIM}↳ {r['detail'][:120]}{NC}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
