"""
chimera/modules/b4_route_addon.py
───────────────────────────────────────────────────────────────────────────────
B4 Route — терминатор эскалации YouTube: туннель в VLESS-exit каскад.

КОНЦЕПЦИЯ (заемная идея hub-сета «YT», переработанная под Chimera):
  Цепочка сетов b4 на entry-ноде:
    Youtube-Fat-v1 (disorder — лёгкие DPI-трюки)
      → escalate → Youtube-Heavy-v1 (tcp — тяжёлые трюки)
      → escalate → Youtube-Route-v1 (routing proxy — туннель)   ← ЭТОТ МОДУЛЬ
  Когда даже Heavy не пробивает ТСПУ, эскалированный хост уходит
  в туннель: b4 TPROXY → SOCKS5 127.0.0.1:<port> (xray socks-inbound
  «b4-route-in») → routing.rule inboundTag → chain-balancer
  (балансёр exit-нод каскада) / chain-exit-N (ручной выбор ноды)
  → выход через чистый транзит exit-ноды.

ПОЧЕМУ НЕТ ПЕТЛИ (критично, см. тему routing.router_traffic в b4):
  Соединение xray→exit идёт на IP exit-ноды (не Google) — route-сет
  его не матчит. Правило inboundTag стоит ПЕРВЫМ в routing.rules —
  ДО ru_subnets и geosite:youtube (youtube_via_ru): иначе geosite-
  правило отправило бы socks-трафик в direct → freedom дозванивается
  до Google с ноды → b4 снова заворачивает в TPROXY → петля
  («box runs out of memory in minutes» — буквальная цитата b4).
  Направлять этот инбаунд в direct/WARP-direct БЕЗ sockopt.mark
  (SelfDialMark b4) нельзя.

АРХИТЕКТУРА (mirror youtube_route.py Pattern C):
  1. _b4r_apply_to_xray(target) — идемпотентный патч конфига Xray:
     socks-inbound (tag B4R_INBOUND_TAG, listen 127.0.0.1, auth
     noauth, udp false) + routing.rule (comment B4R_RULE_COMMENT)
     ПЕРВЫМ в списке правил.
  2. _b4r_remove_from_xray() — чистка inbound + rule по тегу/комменту.
  3. restore_b4_route_if_needed() — re-apply после regenerate config
     (хук в _core.py рядом с restore_youtube_rule_if_needed).
  4. b4-сторона (REST, переиспользует youtube_b4._b4_rest_request):
     self-healing сета — создать если нет (шаблон B4_SET_TEMPLATE),
     синхронизировать upstream.port, включить/выключить
     (batch-set-enabled), проверить эскалацию front-сета
     (escalate.to → Route).
  5. TUI: Настройки сети → BR (боксы box_renderer).
  6. CLI (headless, для деплоя/скриптов): apply / remove / status.

STATE (state.json):
  b4_route_enabled   : bool  — мастер-выключатель (default False)
  b4_route_target    : str   — "balancer" | "chain-exit-N" | "warp"
                               (default "balancer")
  b4_route_port      : int   — порт socks-inbound == upstream.port сета
                               (default 10810; сосед tproxy-telemt = 10811)
  b4_route_set       : str   — имя route-сета в b4
                               (default "Youtube-Route-v1")
  b4_route_front_set : str   — сет-источник эскалации, чей escalate.to
                               указывает на route-сет
                               (default "Youtube-Heavy-v1")

ВЫЗОВ:
  TUI: Настройки сети → BR → B4 Route
  CLI: python3 -m chimera.modules.b4_route_addon apply   [--target ...]
       python3 -m chimera.modules.b4_route_addon remove
       python3 -m chimera.modules.b4_route_addon status
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# ── Логирование (единый формат с остальными модулями) ──────────────────────
_LOG_FILE = Path("/var/log/chimera.log")


def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r"\x1b\[[0-9;]*m", "", msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [b4_route] [{level}] {clean}\n")
    except Exception:
        pass


def _info(msg: str) -> None: print(f"  [INFO]  {msg}"); _log("INFO", msg)
def _ok(msg: str) -> None:   print(f"  [OK]    {msg}"); _log("OK", msg)
def _warn(msg: str) -> None: print(f"  [WARN]  {msg}"); _log("WARN", msg)
def _err(msg: str) -> None:  print(f"  [ERR]   {msg}"); _log("ERR", msg)


# ── box_renderer (UI меню, общий для всех модулей) ────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_item, _box_back,
    _box_info, _box_warn, _box_ok, _box_desc, _box_kv,
)

# ── Делегирование в _core.py (без circular import) ──────────────────────────
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ══════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════

# Тег socks-inbound в конфиге Xray и comment-маркер routing-правила.
# Идемпотентность патча — по этой паре (как youtube_via_ru в youtube_route).
B4R_INBOUND_TAG   = "b4-route-in"
B4R_RULE_COMMENT  = "b4_route_exit"
B4R_INBOUND_PROTO = "socks"

# Порт socks-inbound по умолчанию: соседние локальные слушатели Xray —
# tproxy-telemt на 10811, stats-api на 10085; 10810 продолжает ряд.
B4R_DEFAULT_PORT = 10810

# Дефолтные цели: балансёр каскада (chain-balancer, selector chain-exit-*)
# или конкретная нода chain-exit-N. Живой список целей модуль обнаруживает
# сам по конфигу (outbounds + routing.balancers) — «warp» предлагается
# только если outbound с таким тегом реально существует.
B4R_TARGET_BALANCER = "balancer"
B4R_BALANCER_TAG    = "chain-balancer"
B4R_NODE_TAG_RE     = re.compile(r"^chain-exit-(\d+)$")

# Имена сетов b4 по умолчанию (кастомизируются в настройках модуля).
B4R_DEFAULT_SET       = "Youtube-Route-v1"
B4R_DEFAULT_FRONT_SET = "Youtube-Heavy-v1"

# Проба туннеля: generate_204 от YouTube (ожидаем 2xx-4xx как ок,
# как в b4_monitor._probe_direct) + показ выходного IP в статусе.
B4R_PROBE_URL   = "https://www.youtube.com/generate_204"
B4R_EXIT_IP_URL = "https://api.ipify.org"
B4R_PROBE_TIMEOUT = 10

# Шаблон route-сета b4 для self-healing создания (если сета нет совсем).
# Полностью повторяет выверенный продовый конфиг: чистый routing proxy,
# без DPI-трюков, мишень geoip:google (3018 v4 + 5408 v6 CIDR — строгий
# наднабор goog.json/cloud.json, см. анализ 11.11), QUIC не туннелируем
# (udp off + upstream.udp=false → b4 режет UDP/443 на google-категорию,
# браузеры падают на TCP → в туннель — та же философия, что Fat/Heavy).
B4_SET_TEMPLATE = {
    "name": B4R_DEFAULT_SET,
    "enabled": False,
    "udp": {"mode": "off"},
    "fragmentation": {"strategy": "none"},
    "faking": {"sni": False},
    "targets": {
        "geoip_categories": ["google"],
        "domain_only": False,
        "ip_priority": False,
    },
    "routing": {
        "enabled": True,
        "mode": "proxy",
        "upstream": {
            "host": "127.0.0.1",
            "port": B4R_DEFAULT_PORT,
            "fail_open": False,
            "use_domain": True,
            "udp": False,
        },
    },
    "escalate": {"to": ""},
}


# ══════════════════════════════════════════════════════════════════════════
#  STATE (state.json)
# ══════════════════════════════════════════════════════════════════════════

def _b4r_state_defaults() -> dict:
    return {
        "b4_route_enabled":   False,
        "b4_route_target":    B4R_TARGET_BALANCER,
        "b4_route_port":      B4R_DEFAULT_PORT,
        "b4_route_set":       B4R_DEFAULT_SET,
        "b4_route_front_set": B4R_DEFAULT_FRONT_SET,
    }


def _b4r_load_state() -> dict:
    """Читает ключи b4_route_* из state.json (с дефолтами)."""
    defaults = _b4r_state_defaults()
    try:
        core = _core_module()
        if not core.STATE_FILE.exists():
            return dict(defaults)
        state = json.loads(core.STATE_FILE.read_text())
    except Exception:
        return dict(defaults)
    out = dict(defaults)
    out["b4_route_enabled"] = bool(state.get("b4_route_enabled", False))
    tgt = str(state.get("b4_route_target") or B4R_TARGET_BALANCER)
    out["b4_route_target"] = tgt if _is_valid_target_name(tgt) else B4R_TARGET_BALANCER
    try:
        port = int(state.get("b4_route_port") or B4R_DEFAULT_PORT)
    except (TypeError, ValueError):
        port = B4R_DEFAULT_PORT
    out["b4_route_port"] = port if 1024 <= port <= 65535 else B4R_DEFAULT_PORT
    out["b4_route_set"] = str(state.get("b4_route_set") or B4R_DEFAULT_SET).strip() \
        or B4R_DEFAULT_SET
    out["b4_route_front_set"] = \
        str(state.get("b4_route_front_set") or B4R_DEFAULT_FRONT_SET).strip() \
        or B4R_DEFAULT_FRONT_SET
    return out


def _b4r_save_state(**kwargs) -> dict:
    """Мержит ключи b4_route_* в state.json (атомарно по-read-modify-write)."""
    core = _core_module()
    try:
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
    except Exception:
        state = {}
    state.update(kwargs)
    core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    _log("STATE", f"state.json updated: {sorted(kwargs)}")
    return state


def _is_valid_target_name(target: str) -> bool:
    """«balancer» | «chain-exit-N» | «warp» (существование цели в конфиге
    проверяется отдельно — здесь только формат)."""
    if target == B4R_TARGET_BALANCER or target == "warp":
        return True
    return bool(B4R_NODE_TAG_RE.match(target or ""))


# ══════════════════════════════════════════════════════════════════════════
#  XRAY-СТОРОНА: socks-inbound + routing-правило (идемпотентный патч)
# ══════════════════════════════════════════════════════════════════════════

def _b4r_config_paths() -> list:
    """Пути конфигов Xray (как в youtube_route: оба стандартных, dedup)."""
    core = _core_module()
    paths = []
    for p in (Path(getattr(core, "CONFIG_DIR", "/usr/local/etc/xray")) / "config.json",
              Path("/usr/local/etc/xray/config.json")):
        if not p.exists():
            continue
        try:
            real = str(p.resolve())
        except Exception:
            real = str(p)
        if real not in [x[0] for x in paths]:
            paths.append((real, p))
    return paths


def _b4r_available_targets(cfg: dict) -> dict:
    """Живые цели из конфига Xray: балансёры, ноды chain-exit-N, прочее.

    Returns:
        {"balancers": [tag...], "nodes": [tag...], "extra": [tag...]}
    """
    out = {"balancers": [], "nodes": [], "extra": []}
    for ob in (cfg.get("outbounds") or []):
        tag = str(ob.get("tag") or "")
        if not tag:
            continue
        if B4R_NODE_TAG_RE.match(tag):
            out["nodes"].append(tag)
        elif tag in ("warp",):
            out["extra"].append(tag)
    for b in ((cfg.get("routing") or {}).get("balancers") or []):
        tag = str(b.get("tag") or "")
        if tag:
            out["balancers"].append(tag)
    for key in out:
        out[key] = sorted(set(out[key]))
    return out


def _b4r_build_rule(target: str) -> Optional[dict]:
    """routing-правило для socks-инбаунда под цель.

    balancer → balancerTag (правило-прецедент tproxy-telemt →
    chain-balancer в проде); chain-exit-N/warp → outboundTag.
    """
    rule = {
        "type": "field",
        "inboundTag": [B4R_INBOUND_TAG],
        "comment": B4R_RULE_COMMENT,
    }
    if target == B4R_TARGET_BALANCER:
        rule["balancerTag"] = B4R_BALANCER_TAG
    else:
        rule["outboundTag"] = target
    return rule


def _b4r_build_inbound(port: int) -> dict:
    """socks-inbound на loopback (без авторизации — у upstream-конфига
    b4 нет полей логина; наружу не торчит, listen строго 127.0.0.1)."""
    return {
        "tag": B4R_INBOUND_TAG,
        "listen": "127.0.0.1",
        "port": port,
        "protocol": B4R_INBOUND_PROTO,
        "settings": {"auth": "noauth", "udp": False},
    }


def _b4r_apply_to_xray(target: str, port: int) -> bool:
    """Идемпотентный патч: inbound + правило ПЕРВЫМ. True — хоть один
    конфиг пропатчен. Цель обязана существовать (Xray падает с
    «unknown outbound tag» / «balancer not found») — иначе False без записи.
    """
    core = _core_module()
    _set_config_owner = core._set_config_owner
    if not _is_valid_target_name(target):
        _warn(f"Неизвестный формат цели: {target!r}")
        return False

    written: set = set()
    ok = False
    for real, cfg_path in _b4r_config_paths():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception as e:
            _warn(f"Не удалось прочитать {cfg_path}: {e}")
            continue
        if real in written:
            continue
        written.add(real)

        # Валидация цели по ЖИВОМУ конфигу.
        targets = _b4r_available_targets(cfg)
        if target == B4R_TARGET_BALANCER:
            if B4R_BALANCER_TAG not in targets["balancers"]:
                _warn(f"Балансёр {B4R_BALANCER_TAG} не найден в конфиге Xray "
                      f"(доступны: {targets['balancers'] or '—'})")
                continue
        else:
            pool = targets["nodes"] + targets["extra"]
            if target not in pool:
                _warn(f"Цель {target} не найдена в outbounds Xray "
                      f"(доступны: {', '.join(pool) or '—'})")
                continue

        try:
            routing = cfg.setdefault("routing", {})
            rules = routing.setdefault("rules", [])
            # Идемпотентность: вычищаем старые копии (правило и inbound).
            rules = [r for r in rules if r.get("comment") != B4R_RULE_COMMENT
                     and B4R_INBOUND_TAG not in (r.get("inboundTag") or [])]
            inbounds = [i for i in cfg.setdefault("inbounds", [])
                        if i.get("tag") != B4R_INBOUND_TAG]
            inbounds.append(_b4r_build_inbound(port))
            # Правило ПЕРВЫМ: Xray eval top-to-bottom, первое совпадение
            # выигрывает. Критично: ниже по списку стоит geosite:youtube →
            # direct (youtube_via_ru) — если оно перехватит socks-трафик,
            # получим TPROXY-петлю (см. докстринг модуля).
            routing["rules"] = [_b4r_build_rule(target)] + rules
            cfg["inbounds"] = inbounds
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            _info(f"Конфиг: {cfg_path} (socks 127.0.0.1:{port} → {target})")
            ok = True
        except Exception as e:
            _warn(f"Ошибка патча {cfg_path}: {e}")

    if not ok:
        return False

    # Безопасный рестарт (start-limit-fix, mirror youtube_route):
    # reset-failed → restart → короткая пауза на поднятие.
    _safe_restart = getattr(core, "_xray_safe_restart", None)
    if callable(_safe_restart):
        _safe_restart()
    else:  # fallback на старое поведение (старое ядро без хелпера)
        core._run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        core._run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(0.5)
    return True


def _b4r_remove_from_xray() -> bool:
    """Убирает inbound + правило из всех конфигов (идемпотентно)."""
    core = _core_module()
    _set_config_owner = core._set_config_owner
    written: set = set()
    ok = False
    for real, cfg_path in _b4r_config_paths():
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception as e:
            _warn(f"Не удалось прочитать {cfg_path}: {e}")
            continue
        routing = cfg.setdefault("routing", {})
        before_rules = len(routing.setdefault("rules", []))
        routing["rules"] = [
            r for r in routing["rules"]
            if r.get("comment") != B4R_RULE_COMMENT
            and B4R_INBOUND_TAG not in (r.get("inboundTag") or [])]
        before_in = len(cfg.setdefault("inbounds", []))
        cfg["inbounds"] = [i for i in cfg["inbounds"]
                           if i.get("tag") != B4R_INBOUND_TAG]
        if len(routing["rules"]) == before_rules and len(cfg["inbounds"]) == before_in:
            continue  # патча тут не было — рестарт не нужен
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        _set_config_owner(cfg_path)
        _info(f"Конфиг очищен: {cfg_path}")
        ok = True
    if not ok:
        return True  # чистить нечего — это успех (идемпотентность)
    _safe_restart = getattr(core, "_xray_safe_restart", None)
    if callable(_safe_restart):
        _safe_restart()
    else:
        core._run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        core._run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(0.5)
    return True


def _b4r_xray_state() -> dict:
    """Снимок xray-стороны для статуса/restore: есть ли патч и его параметры."""
    state = {"patched": False, "port": None, "target": None, "targets_available": {}}
    for real, cfg_path in _b4r_config_paths():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            continue
        state["targets_available"] = _b4r_available_targets(cfg)
        inbound = next((i for i in (cfg.get("inbounds") or [])
                        if i.get("tag") == B4R_INBOUND_TAG), None)
        rule = next((r for r in ((cfg.get("routing") or {}).get("rules") or [])
                     if r.get("comment") == B4R_RULE_COMMENT), None)
        if inbound or rule:
            state["patched"] = True
            state["port"] = inbound.get("port") if inbound else None
            target = (rule.get("balancerTag") or rule.get("outboundTag")) \
                if rule else None
            # Нормализация к логической цели state: «balancer» в state —
            # это balancerTag B4R_BALANCER_TAG в конфиге (иначе restore
            # не узнаёт «патч на месте» и перезаписывает каждый раз).
            if target == B4R_BALANCER_TAG:
                target = B4R_TARGET_BALANCER
            state["target"] = target
        break  # достаточно первого существующего конфига
    return state


def restore_b4_route_if_needed(silent: bool = False) -> bool:
    """Re-apply после regenerate xray-config (хук из _core.py):
    state говорит «включено», а патча в конфиге нет → применить заново.
    """
    st = _b4r_load_state()
    if not st["b4_route_enabled"]:
        return False
    xs = _b4r_xray_state()
    if xs["patched"] and xs["port"] == st["b4_route_port"] \
            and xs["target"] == st["b4_route_target"]:
        return False
    if not silent:
        _info("Regenerate обнаружен: восстанавливаю B4 Route-патч Xray")
    return _b4r_apply_to_xray(st["b4_route_target"], st["b4_route_port"])


# ══════════════════════════════════════════════════════════════════════════
#  B4-СТОРОНА: REST API (переиспользуем клиент youtube_b4 — 127.0.0.1:9700)
# ══════════════════════════════════════════════════════════════════════════

def _b4r_rest(method: str, path: str, payload: Optional[dict] = None):
    """Обёртка над youtube_b4._b4_rest_request (lazy import, web-auth
    b4 отключён — токен не нужен, но клиент умеет и с ним)."""
    from chimera.modules.youtube_b4 import _b4_rest_request
    return _b4_rest_request(method, path, payload)


def _b4r_sets_list() -> Optional[list]:
    """GET /api/sets → список сетов (устойчиво к формату ответа:
    b4 отвечает ПЛОСКИМ МАССИВОМ [{...}, ...] — как ожидает и
    youtube_b4._b4_rest_import_set (isinstance(sets, list)); dict-обёртка
    {"sets": [...]} допускается как толерантность к будущим версиям).
    None — REST недоступен."""
    resp = _b4r_rest("GET", "/api/sets")
    if not resp or resp[0] != 200:
        return None
    body = resp[1]
    if isinstance(body, dict):
        body = body.get("sets") or []
    if not isinstance(body, list):
        return None
    return body


def _b4r_find_b4_set(name: str) -> Optional[dict]:
    """Ищет сет по имени → полный объект сета (с revision) или None."""
    sets = _b4r_sets_list()
    if sets is None:
        return None
    for s in sets:
        if isinstance(s, dict) and str(s.get("name") or "") == name:
            # Полный объект: GET /api/sets/{id} (с revision для PUT).
            one = _b4r_rest("GET", f"/api/sets/{s.get('id')}")
            if one and one[0] == 200 and isinstance(one[1], dict):
                return one[1]
            return s
    return None


def _b4r_ensure_b4_set(name: str, port: int) -> Optional[dict]:
    """Self-healing route-сета: создать по шаблону если нет,
    поправить upstream.port если разошёлся. Возвращает объект сета."""
    existing = _b4r_find_b4_set(name)
    if existing is None:
        template = json.loads(json.dumps(B4_SET_TEMPLATE))  # deep copy
        template["name"] = name
        template["routing"]["upstream"]["port"] = port
        resp = _b4r_rest("POST", "/api/sets", template)
        if not resp or resp[0] not in (200, 201):
            _err(f"b4 REST: не удалось создать сет {name}: {resp}")
            return None
        _ok(f"b4: сет {name} создан по шаблону (routing proxy → 127.0.0.1:{port})")
        return _b4r_find_b4_set(name)

    upstream = ((existing.get("routing") or {}).get("upstream") or {})
    mode = (existing.get("routing") or {}).get("mode")
    if mode != "proxy" or str(upstream.get("host") or "") != "127.0.0.1" \
            or upstream.get("port") != port:
        existing["routing"] = json.loads(json.dumps(B4_SET_TEMPLATE["routing"]))
        existing["routing"]["upstream"]["port"] = port
        resp = _b4r_rest("PUT", f"/api/sets/{existing.get('id')}", existing)
        if not resp or resp[0] != 200:
            _err(f"b4 REST: не удалось синхронизировать upstream сета {name}: {resp}")
            return None
        _ok(f"b4: upstream сета {name} синхронизирован (127.0.0.1:{port}, mode=proxy)")
    return existing


def _b4r_set_enabled(name: str, enabled: bool) -> bool:
    """Вкл/выкл сета через batch-set-enabled (hot-reload, без рестарта b4)."""
    s = _b4r_find_b4_set(name)
    if s is None:
        _err(f"b4: сет {name} не найден")
        return False
    if bool(s.get("enabled")) == enabled:
        return True  # уже в нужном состоянии
    resp = _b4r_rest("POST", "/api/sets/batch-set-enabled",
                     {"ids": [s.get("id")], "enabled": enabled})
    if not resp or resp[0] != 200:
        _err(f"b4 REST: batch-set-enabled failed: {resp}")
        return False
    _ok(f"b4: сет {name} {'включён' if enabled else 'выключен'}")
    return True


def _b4r_ensure_escalation(front_name: str, route_name: str) -> bool:
    """Проверяет/прописывает front-сету escalate.to = id route-сета
    (sanitizeEscalation b4 хранит ссылки на disabled-сеты — цепь можно
    собирать заранее, активируется включением route-сета)."""
    route = _b4r_find_b4_set(route_name)
    front = _b4r_find_b4_set(front_name)
    if route is None or front is None:
        _warn(f"b4: сеты {front_name!r}/{route_name!r} не найдены — "
              f"эскалация не проверена")
        return False
    if str((front.get("escalate") or {}).get("to") or "") == str(route.get("id")):
        return True
    front.setdefault("escalate", {})["to"] = str(route.get("id"))
    resp = _b4r_rest("PUT", f"/api/sets/{front.get('id')}", front)
    if not resp or resp[0] != 200:
        _err(f"b4 REST: не удалось прописать эскалацию {front_name} → {route_name}")
        return False
    _ok(f"b4: эскалация {front_name} → {route_name} прописана")
    return True


def _b4r_b4_status() -> dict:
    """Снимок b4-стороны для статуса/TUI."""
    st = _b4r_load_state()
    out = {"rest_ok": False, "set": None, "front": None, "escalation_ok": None}
    sets = _b4r_sets_list()
    if sets is not None:
        out["rest_ok"] = True
        out["set"] = _b4r_find_b4_set(st["b4_route_set"])
        out["front"] = _b4r_find_b4_set(st["b4_route_front_set"])
        if out["set"] and out["front"]:
            out["escalation_ok"] = \
                str((out["front"].get("escalate") or {}).get("to") or "") \
                == str(out["set"].get("id"))
    return out


# ══════════════════════════════════════════════════════════════════════════
#  ПРОБЫ ТУННЕЛЯ
# ══════════════════════════════════════════════════════════════════════════

def _b4r_curl(args: list, timeout: int = B4R_PROBE_TIMEOUT) -> tuple:
    """curl с таймаутом → (rc, stdout). errors='replace' — IP может не прийти."""
    try:
        p = subprocess.run(["curl", "-sS", "-m", str(timeout)] + args,
                           capture_output=True, text=True, timeout=timeout + 5)
        return p.returncode, (p.stdout or "").strip()
    except Exception as e:
        return 1, str(e)


def _b4r_probe(port: int) -> dict:
    """Проба туннеля: YouTube generate_204 ЧЕРЕЗ socks (путь эскалированного
    хоста). ok = HTTP 2xx-4xx (как b4_monitor._probe_direct)."""
    rc, out = _b4r_curl([
        "--socks5-hostname", f"127.0.0.1:{port}",
        "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
        B4R_PROBE_URL,
    ])
    parts = out.split()
    code = parts[0] if parts else ""
    t = parts[1] if len(parts) > 1 else "?"
    ok = rc == 0 and code[:1] in ("2", "3", "4")
    return {"ok": ok, "http_code": code or f"rc={rc}", "time_s": t}


def _b4r_exit_ip(port: int) -> str:
    """Выходной IP туннеля (показ в статусе; None-строка при неудаче)."""
    rc, out = _b4r_curl(["--socks5-hostname", f"127.0.0.1:{port}", B4R_EXIT_IP_URL])
    ip = out.strip().splitlines()[0].strip() if out.strip() else ""
    if rc == 0 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]{2,}$", ip or ""):
        return ip
    return "—"


# ══════════════════════════════════════════════════════════════════════════
#  HIGH-LEVEL: apply / remove
# ══════════════════════════════════════════════════════════════════════════

def _b4r_youtube_ru_ok(ensure: bool = False) -> bool:
    """YouTube через RU должен быть ВКЛЮЧЕН: иначе весь YouTube уже уходит
    в exit-каскад на уровне Xray (catch-all) и route-сет не имеет смысла.
    ensure=True — перевести в «ru» (запрос владельца: «если нужно —
    переведи в нужное состояние»); TUI спрашивает явно."""
    try:
        core = _core_module()
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
        target = str(state.get("youtube_route_target") or ("ru" if state.get("youtube_via_ru") else "off"))
    except Exception:
        target = "off"
    if target == "ru":
        return True
    if not ensure:
        _warn("YouTube сейчас НЕ через RU entry (youtube_route_target="
              f"{target!r}) — эскалация в туннель не имеет смысла: весь "
              "YouTube уже уходит в exit-каскад catch-all'ом Xray")
        return False
    from chimera.modules.youtube_route import (
        _youtube_apply_to_xray, _save_youtube_state)
    if not _youtube_apply_to_xray(None):
        _err("Не удалось переключить YouTube → RU entry (см. youtube_route)")
        return False
    _save_youtube_state("ru")
    _ok("YouTube переключён на RU entry (youtube_route_target=ru) — "
        "база для работы B4 Route создана")
    return True


def b4_route_apply(target: Optional[str] = None, port: Optional[int] = None,
                   ensure_youtube_ru: bool = False,
                   set_name: Optional[str] = None,
                   front_set_name: Optional[str] = None) -> dict:
    """Полное включение: xray-патч + self-healing сета + эскалация +
    включение сета + state. Возвращает отчёт-словарь (для CLI/TUI)."""
    st = _b4r_load_state()
    target = target or st["b4_route_target"]
    port = int(port or st["b4_route_port"])
    set_name = set_name or st["b4_route_set"]
    front_set_name = front_set_name or st["b4_route_front_set"]

    report = {"ok": False, "target": target, "port": port,
              "set": set_name, "front_set": front_set_name}

    # 1. База: YouTube через RU entry (иначе эскалации нечему спасать).
    if not _b4r_youtube_ru_ok(ensure=ensure_youtube_ru):
        report["error"] = "youtube_not_via_ru"
        return report

    # 2. Xray: socks-inbound + правило (первым).
    if not _b4r_apply_to_xray(target, port):
        report["error"] = "xray_patch_failed"
        return report
    report["xray_patched"] = True

    # 3. b4: self-healing сета + эскалация + включение.
    s = _b4r_ensure_b4_set(set_name, port)
    if s is None:
        report["error"] = "b4_set_failed"
        return report
    if not _b4r_ensure_escalation(front_set_name, set_name):
        report["escalation_ok"] = False  # не фатально: сеть уже поднята
    else:
        report["escalation_ok"] = True
    if not _b4r_set_enabled(set_name, True):
        report["error"] = "b4_enable_failed"
        return report

    # 4. Проба туннеля (не фатальна для apply — статус покажет).
    report["probe"] = _b4r_probe(port)

    # 5. State.
    _b4r_save_state(b4_route_enabled=True, b4_route_target=target,
                    b4_route_port=port, b4_route_set=set_name,
                    b4_route_front_set=front_set_name)
    report["ok"] = True
    _ok(f"B4 Route ВКЛЮЧЁН: socks 127.0.0.1:{port} → {target}, "
        f"сет {set_name} активен, эскалация {front_set_name} → {set_name}")
    return report


def b4_route_remove() -> dict:
    """Полное выключение: сет off → xray-патч снят → state off.
    Эскалацию front-сета НЕ трогаем (валидатор b4 хранит ссылку на
    disabled-сет — включение Route мгновенно оживит цепь)."""
    st = _b4r_load_state()
    report = {"ok": True}
    _b4r_set_enabled(st["b4_route_set"], False)
    report["b4_set_disabled"] = True
    if not _b4r_remove_from_xray():
        report["ok"] = False
        report["error"] = "xray_unpatch_failed"
        return report
    report["xray_unpatched"] = True
    _b4r_save_state(b4_route_enabled=False)
    _ok("B4 Route ВЫКЛЮЧЕН: патч Xray снят, сет выключен "
        "(эскалация во «сне» — включение Route оживит цепь)")
    return report


def b4_route_status() -> dict:
    """Полный статус для CLI/TUI: state + xray + b4 + проба."""
    st = _b4r_load_state()
    xs = _b4r_xray_state()
    b4 = _b4r_b4_status()
    out = {
        "state": st,
        "xray": {k: xs[k] for k in ("patched", "port", "target")},
        "xray_targets": xs["targets_available"],
        "b4_rest_ok": b4["rest_ok"],
        "b4_set": None,
        "escalation_ok": b4["escalation_ok"],
        "probe": None,
        "exit_ip": None,
    }
    if b4["set"]:
        r = b4["set"].get("routing") or {}
        u = r.get("upstream") or {}
        out["b4_set"] = {
            "name": b4["set"].get("name"),
            "enabled": bool(b4["set"].get("enabled")),
            "mode": r.get("mode"),
            "upstream": f"{u.get('host')}:{u.get('port')}",
            "geoip": ((b4["set"].get("targets") or {}).get("geoip_categories") or []),
        }
    if st["b4_route_enabled"] and xs["patched"]:
        out["probe"] = _b4r_probe(st["b4_route_port"])
        out["exit_ip"] = _b4r_exit_ip(st["b4_route_port"])
    return out


# ══════════════════════════════════════════════════════════════════════════
#  TUI (Настройки сети → BR)
# ══════════════════════════════════════════════════════════════════════════

def _b4r_target_label(target: str) -> str:
    if target == B4R_TARGET_BALANCER:
        return f"Балансёр ({B4R_BALANCER_TAG})"
    if target == "warp":
        return "WARP"
    return f"Нода {target}"


def _b4r_status_view() -> None:
    """Отрисовка статуса (боксы)."""
    s = b4_route_status()
    st, xs = s["state"], s["xray"]
    _box_top("B4 Route — статус и диагностика")
    _box_kv("Мастер-выключатель", "ВКЛЮЧЁН" if st["b4_route_enabled"] else "выключен")
    _box_kv("Цель туннеля", _b4r_target_label(st["b4_route_target"]))
    _box_kv("Socks-порт", str(st["b4_route_port"]))
    _box_kv("Сет b4", st["b4_route_set"])
    _box_kv("Front-сет эскалации", st["b4_route_front_set"])
    _box_sep()
    _box_kv("Xray-патч", "на месте" if xs["patched"] else "ОТСУТСТВУЕТ")
    if xs["patched"]:
        _box_kv("Правило", f"inboundTag → {xs['target'] or '?'} "
                           f"(порт {xs['port'] or '?'})")
    _box_kv("b4 REST", "доступен" if s["b4_rest_ok"] else "НЕДОСТУПЕН")
    if s["b4_set"]:
        _box_kv("Сет в b4",
                f"{'включён' if s['b4_set']['enabled'] else 'выключен'}, "
                f"{s['b4_set']['mode']} → {s['b4_set']['upstream']}, "
                f"geoip: {','.join(s['b4_set']['geoip']) or '—'}")
    _box_kv("Эскалация → Route",
            "прописана" if s["escalation_ok"] else ("НЕ прописана" if s["escalation_ok"] is False else "?"))
    if s["probe"]:
        p = s["probe"]
        _box_sep()
        _box_kv("Проба туннеля",
                f"{'OK' if p['ok'] else 'FAIL'} (HTTP {p['http_code']}, {p['time_s']} c)")
        _box_kv("Выходной IP туннеля", str(s["exit_ip"]))
    _box_sep()
    _box_desc("Цепочка: Fat (disorder) → Heavy (tcp) → Route (туннель). "
              "Route берёт только эскалированные хосты — здоровый YouTube "
              "как шёл через RU-direct, так и идёт.")
    _box_bottom()


def _b4r_pick_node_view(xs_targets: dict) -> Optional[str]:
    """Подменю ручного выбора ноды: только живые цели из конфига.
    Возвращает «chain-exit-N» / «warp» / «balancer» или None (назад)."""
    nodes = xs_targets.get("nodes") or []
    extras = xs_targets.get("extra") or []
    balancers = xs_targets.get("balancers") or []
    if not nodes and not extras:
        _box_top("B4 Route — выбор ноды")
        _box_warn("В конфиге Xray не найдено ни одной exit-ноды (chain-exit-N)")
        _box_bottom()
        input("Нажмите Enter...")
        return None
    _box_top("B4 Route — ручной выбор ноды")
    _box_desc("Туннель уйдёт строго через выбранную ноду. Рекомендуется "
              "балансёр (пункт B в основном меню): сам держит нагрузку "
              "на самой оптимальной из нод.")
    _box_sep()
    keys = []
    for i, tag in enumerate(nodes, 1):
        _box_item(str(i), f"Нода {tag}")
        keys.append((str(i), tag))
    for j, tag in enumerate(extras, 1):
        key = f"W{j}"
        _box_item(key, f"{tag} (дополнительный outbound)")
        keys.append((key, tag))
    _box_sep()
    _box_item("A", f"Балансёр {', '.join(balancers) or B4R_BALANCER_TAG}")
    keys.append(("A", B4R_TARGET_BALANCER))
    _box_back()
    _box_bottom()
    try:
        ch = input("Выбор: ").strip().upper()
    except (KeyboardInterrupt, EOFError):
        return None
    for key, tag in keys:
        if ch == key:
            return tag
    return None


def _b4r_settings_view() -> None:
    """Подменю настроек: порт, имя сета, front-сет."""
    while True:
        st = _b4r_load_state()
        _box_top("B4 Route — настройки")
        _box_kv("Socks-порт", str(st["b4_route_port"]))
        _box_kv("Сет b4", st["b4_route_set"])
        _box_kv("Front-сет эскалации", st["b4_route_front_set"])
        _box_sep()
        _box_item("1", "Изменить порт (xray inbound + upstream сета)")
        _box_item("2", "Изменить имя route-сета b4")
        _box_item("3", "Изменить имя front-сета (источник эскалации)")
        _box_back()
        _box_bottom()
        try:
            ch = input("Выбор: ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if ch == "0" or ch.lower() == "q":
            return
        if ch == "1":
            try:
                raw = input("Новый порт (1024-65535): ").strip()
                port = int(raw)
            except ValueError:
                _warn("Порт должен быть числом"); continue
            if not (1024 <= port <= 65535):
                _warn("Порт вне диапазона 1024-65535"); continue
            _b4r_save_state(b4_route_port=port)
            if st["b4_route_enabled"]:
                _info("Применю новый порт повторным apply...")
                b4_route_apply(port=port)
            else:
                _ok(f"Порт сохранён: {port}")
        elif ch in ("2", "3"):
            key = "b4_route_set" if ch == "2" else "b4_route_front_set"
            label = "route-сет" if ch == "2" else "front-сет"
            try:
                raw = input(f"Имя {label} (текущий: {st[key]}): ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if raw:
                _b4r_save_state(**{key: raw})
                _ok(f"{label.capitalize()} сохранён: {raw}")


def do_manage_b4_route() -> None:
    """TUI-меню модуля (Настройки сети → BR)."""
    while True:
        st = _b4r_load_state()
        xs = _b4r_xray_state()
        _box_top("B4 Route — эскалация YouTube → VLESS-exit")
        _box_desc("Терминатор цепочки сетов b4: Fat (disorder) → Heavy (tcp) "
                  "→ Route (туннель). Когда тяжёлые DPI-трюки не пробивают "
                  "ТСПУ, эскалированный хост уходит в socks-туннель Xray "
                  "→ exit-каскад. Здоровый YouTube остаётся на RU-direct.")
        _box_sep()
        _box_kv("Состояние", "ВКЛЮЧЁН" if st["b4_route_enabled"] else "выключен")
        _box_kv("Цель", _b4r_target_label(st["b4_route_target"]))
        _box_kv("Xray-патч", "на месте" if xs["patched"] else "отсутствует")
        _box_sep()
        _box_item("1", "Включить через БАЛАНСЁР (любая из нод каскада — рекомендовано)")
        _box_item("2", "Включить через конкретную НОДУ (ручной выбор)")
        _box_item("3", "Выключить")
        _box_item("4", "Настройки (порт / имена сетов)")
        _box_item("5", "Статус и диагностика (проба туннеля)")
        _box_back()
        _box_bottom()
        try:
            ch = input("Выбор: ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if ch == "0" or ch.lower() == "q":
            return
        if ch == "1":
            b4_route_apply(target=B4R_TARGET_BALANCER, ensure_youtube_ru=True)
            input("Нажмите Enter...")
        elif ch == "2":
            tag = _b4r_pick_node_view(xs.get("targets_available") or {})
            if tag:
                b4_route_apply(target=tag, ensure_youtube_ru=True)
                input("Нажмите Enter...")
        elif ch == "3":
            b4_route_remove()
            input("Нажмите Enter...")
        elif ch == "4":
            _b4r_settings_view()
        elif ch == "5":
            _b4r_status_view()
            input("Нажмите Enter...")


# ══════════════════════════════════════════════════════════════════════════
#  CLI (headless)
# ══════════════════════════════════════════════════════════════════════════

def _cli() -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="b4_route_addon",
        description="B4 Route — терминатор эскалации YouTube (туннель в VLESS-exit)")
    p.add_argument("cmd", choices=["apply", "remove", "status", "menu"],
                   help="apply — включить; remove — выключить; "
                        "status — JSON-снимок; menu — TUI")
    p.add_argument("--target", default=None,
                   help="balancer | chain-exit-N | warp (default: из state)")
    p.add_argument("--port", type=int, default=None,
                   help="порт socks-inbound (default: из state)")
    p.add_argument("--set-name", default=None, help="имя route-сета b4")
    p.add_argument("--front-set-name", default=None, help="имя front-сета")
    p.add_argument("--ensure-youtube-ru", action="store_true",
                   help="если YouTube не через RU — переключить на RU")
    args = p.parse_args()
    if args.cmd == "apply":
        rep = b4_route_apply(target=args.target, port=args.port,
                             ensure_youtube_ru=args.ensure_youtube_ru,
                             set_name=args.set_name,
                             front_set_name=args.front_set_name)
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep.get("ok") else 1
    if args.cmd == "remove":
        rep = b4_route_remove()
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep.get("ok") else 1
    if args.cmd == "status":
        print(json.dumps(b4_route_status(), ensure_ascii=False, indent=2))
        return 0
    do_manage_b4_route()
    return 0


if __name__ == "__main__":
    sys.exit(_cli())

