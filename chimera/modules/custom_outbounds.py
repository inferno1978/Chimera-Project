#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chimera/modules/custom_outbounds.py
───────────────────────────────────────────────────────────────────────────────
Кастомные outbound'ы Xray — свои ноды / серверы друзей прямо в живом конфиге.

Запрос клиента (04.11, скриншот меню «Куда направить трафик РФ-подсетей?»):
«в режиме А можно как-то добавить outbound?» — раньше в пикерах outbound
(импорт РФ-подсетей, routing-правила) можно было выбрать только существующие
теги (chain-exit-N, direct, BLOCK) или «ввести тег вручную» — но ручной тег
НЕ создавал сам outbound: правило честно смотрело в пустоту, трафик по нему
отбрасывался. Теперь мастер создаёт полноценный outbound и он сразу виден
во всех пикерах.

Возможности:
  • Импорт по ссылке: vless:// (REALITY/TLS, tcp/ws/grpc/httpupgrade/xhttp/
    kcp/quic/http), vmess:// (base64-JSON), trojan://, ss:// (SIP002 + legacy)
  • Мастер: vless / vmess / trojan / shadowsocks / socks / http — форма
    по протоколу + транспорт + security (none/tls/reality)
  • Готовый однострочный JSON outbound (v2rayN / Xray-формат)
  • Вкл/выкл, удаление (с проверкой ссылок из routing.rules), TCP-проверка
    доступности, просмотр JSON, пере-применение
  • Survive-regenerate: restore_custom_outbounds_if_needed вызывается из
    _core._rebuild_and_restart_xray ПЕРВЫМ из restore-хуков — dns_custom:*
    и custom:* routing-правила могут ссылаться на кастомные теги
  • Валидация живым `xray run -test` + откат конфига и state при ошибке

State:      /var/lib/xray-installer/custom_outbounds.json (0600):
            {outbounds: [entry…], known_tags: [когда-либо созданные теги]}
            (known_tags — источник правды для удаления: без него удаление
            последнего entry теряло тег → осиротевший outbound в конфиге)
Применение: append в outbounds[] /etc/xray/config.json (+ альтернативный
            /usr/local/etc/xray/config.json), удаление/пере-добавление по
            тегу. Дефолтный outbound (первый в списке) не трогаем — кастомные
            всегда в конец; без routing-правила на тег трафик туда не идёт.

ОГРАНИЧЕНИЕ (честно): outbound доступен всем клиентам сервера сразу —
Xray routing не разделяет трафик по пользователям.

Точки входа:
    from chimera.modules.custom_outbounds import (
        do_manage_custom_outbounds, restore_custom_outbounds_if_needed,
        co_create_outbound_inline, co_state_tags,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import uuid as _uuid_mod
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from chimera.modules.tui import tui_form, tui_select, tui_confirm, TuiField
from chimera.modules.box_renderer import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    _box_top, _box_bottom, _box_sep, _box_row, _box_item,
    _box_back, _box_desc, _box_kv, _box_warn, _box_ok,
)

# ── Константы ─────────────────────────────────────────────────────────────────
CO_STATE_FILE  = Path("/var/lib/xray-installer/custom_outbounds.json")
CO_TAG_RE      = re.compile(r'^[a-z0-9][a-z0-9._-]{1,63}$')
CO_PROTOCOLS   = ("vless", "vmess", "trojan", "shadowsocks", "socks", "http")
CO_NETWORKS    = ("tcp", "ws", "grpc", "httpupgrade", "xhttp")
CO_METHODS     = ("chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm",
                  "2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm",
                  "2022-blake3-chacha20-poly1305")
CO_FPS         = ("chrome", "firefox", "safari", "ios", "android",
                  "edge", "random")
CO_SRC_LABELS  = {"link": "🔗 ссылка", "wizard": "🎛 мастер", "json": "⌷ JSON"}

_CONFIG_DIR = Path("/etc/xray")
_ALT_CONFIG = Path("/usr/local/etc/xray/config.json")
_XRAY_BIN   = "/usr/local/bin/xray"
_LOG_FILE   = Path("/var/log/chimera.log")


# ══════════════════════════════════════════════════════════════════════════════
#  ЛОГИРОВАНИЕ (канон routing_rules: /var/log/chimera.log + changes.json)
# ══════════════════════════════════════════════════════════════════════════════

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] [custom_outbounds] {clean}\n")
    except Exception:
        pass


def _success(msg: str) -> None:
    print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)


def _warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)


def _info(msg: str) -> None:
    print(f"{CYAN}[..]{NC}    {msg}"); _log("INFO", msg)


def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace")
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


def _co_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
        entries.append({"ts": _co_now(), "key": key, "detail": detail})
        ch_file.parent.mkdir(parents=True, exist_ok=True)
        ch_file.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  STATE I/O
# ══════════════════════════════════════════════════════════════════════════════

def _co_load() -> dict:
    try:
        if CO_STATE_FILE.exists():
            data = json.loads(CO_STATE_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {"version": 1, "outbounds": []}


def _co_save(data: dict) -> None:
    CO_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data.setdefault("version", 1)
    CO_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    CO_STATE_FILE.chmod(0o600)


def co_state_tags() -> set:
    """Теги всех кастомных outbound'ов (для маркировки 🔗 в пикерах)."""
    return {e.get("name") for e in _co_load().get("outbounds", [])
            if isinstance(e, dict) and e.get("name")}


# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ XRAY
# ══════════════════════════════════════════════════════════════════════════════

def _co_iter_configs() -> list:
    """Все живые конфиги Xray (path, cfg), dedup по realpath (канон rr)."""
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


def _co_live_tags() -> set:
    """Теги outbounds из живого конфига (первый найденный)."""
    configs = _co_iter_configs()
    if not configs:
        return set()
    _, cfg = configs[0]
    return {o.get("tag", "") for o in cfg.get("outbounds", []) if o.get("tag")}


def _co_apply_to_xray(restart: bool = False, validate: bool = False,
                      silent: bool = False) -> bool:
    """Синхронизирует state → outbounds[] всех живых конфигов.

    Атомарно: сначала удаляет из outbounds[] ВСЕ наши теги — живые entries
    плюс known_tags (когда-либо созданные; без них удаление последнего
    entry из state теряло знание о теге → осиротевший outbound в конфиге
    навсегда, вскрыто E2E) — потом добавляет включённые в КОНЕЦ списка
    (дефолтный outbound — первый в списке — не трогаем). validate=True —
    `xray run -test` после записи; при ошибке откатывает конфиги к
    исходному тексту и возвращает False. Успех → known_tags в state.
    """
    configs = _co_iter_configs()
    if not configs:
        if not silent:
            _warn("Xray конфиг не найден")
        return False

    state    = _co_load()
    entries  = [e for e in state.get("outbounds", [])
                if isinstance(e, dict) and e.get("name")]
    known    = {str(t) for t in state.get("known_tags", []) if t}
    cur      = {e["name"] for e in entries}
    all_tags = known | cur
    enabled  = [e for e in entries if e.get("enabled", True)]

    snapshots = {str(p): p.read_text() for p, _ in configs}

    for path, cfg in configs:
        try:
            obs = [o for o in cfg.get("outbounds", [])
                   if o.get("tag") not in all_tags]
            for e in enabled:
                ob = json.loads(json.dumps(e.get("outbound", {})))  # deep copy
                ob["tag"] = e["name"]
                obs.append(ob)
            cfg["outbounds"] = obs
            path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(path)
        except Exception as ex:
            if not silent:
                _warn(f"Ошибка патча {path}: {ex}")
            return False

    if validate:
        for path, _ in configs:
            val = _run([_XRAY_BIN, "run", "-test", "-config", str(path)],
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

    # Успех → запомнить наши теги (источник правды для удаления сирот)
    if all_tags != known:
        try:
            state2 = _co_load()
            state2["known_tags"] = sorted(all_tags)
            _co_save(state2)
        except Exception:
            pass

    if restart:
        _co_reload_xray(silent=silent)

    if not silent and enabled:
        _info(f"Кастомных outbound'ов в конфиге: {len(enabled)}"
              + (f" (выключено: {len(entries) - len(enabled)})" if len(entries) > len(enabled) else ""))
    return True


def _co_reload_xray(silent: bool = False) -> bool:
    """Безопасный рестарт (start-limit-fix, канон routing_rules)."""
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
            _success("Xray перезапущен с кастомными outbound'ами")
        return True
    _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    time.sleep(2)
    ok = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if ok.stdout.strip() == "active":
        if not silent:
            _success("Xray перезапущен с кастомными outbound'ами")
        return True
    if not silent:
        _warn("Xray не запустился — проверьте конфиг! journalctl -u xray -n 30")
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  RESTORE (после regenerate — вызывается ПЕРВЫМ из restore-хуков _core)
# ══════════════════════════════════════════════════════════════════════════════

def restore_custom_outbounds_if_needed(silent: bool = False) -> bool:
    """Пере-добавляет кастомные outbound'ы, если state говорит что они
    включены, но в живом конфиге их нет (generate_* перезаписывает
    outbounds[] целиком — без restore кастомные ноды молча терялись при
    каждой пересборке: смена домена/порта, regenerate 5b и т.д.).

    Вызывается из _core._rebuild_and_restart_xray ПЕРВЫМ из restore-хуков
    (до dns_custom/custom routing-restore): правила могут ссылаться на
    кастомные теги — outbound должен существовать к моменту их re-apply.
    Перезапуск Xray делает вызывающий код. Возвращает True если
    outbound'ы были пере-применены.
    """
    state   = _co_load()
    enabled = [e for e in state.get("outbounds", [])
               if isinstance(e, dict) and e.get("enabled", True)
               and e.get("name")]
    if not enabled:
        return False

    live = set()
    for _p, cfg in _co_iter_configs():
        live |= {o.get("tag", "") for o in cfg.get("outbounds", [])}
    need = {e["name"] for e in enabled}
    if need <= live:
        return False  # всё уже на месте

    missing = need - live
    if not silent:
        _info(f"Восстанавливаем кастомные outbound'ы после regenerate "
              f"(потеряно: {len(missing)} из {len(need)})...")
    ok = _co_apply_to_xray(restart=False, validate=True, silent=silent)
    if ok and not silent:
        _success(f"Кастомные outbound'ы восстановлены "
                 f"({len(enabled)} из state)")
    return ok


# ══════════════════════════════════════════════════════════════════════════════
#  ПАРСЕРЫ ССЫЛОК (vless:// vmess:// trojan:// ss://) + JSON
# ══════════════════════════════════════════════════════════════════════════════

def _b64_decode(s: "str | bytes") -> bytes:
    """Base64 со всеми вариантами алфавита и без паддинга."""
    if isinstance(s, bytes):
        s = s.decode("utf-8", "replace")
    s = s.strip()
    if not s:
        raise ValueError("пустая base64-строка")
    pad = "=" * (-len(s) % 4)
    for cand in (s + pad, s.replace("-", "+").replace("_", "/") + pad):
        try:
            return base64.b64decode(cand)
        except Exception:
            continue
    raise ValueError("не похоже на base64")


def _split_hostport(hp: str) -> "tuple[str, int]":
    """host:port / [v6]:port / host:port/ — без urlparse."""
    hp = hp.strip().rstrip("/")
    if not hp:
        raise ValueError("нет host:port")
    if hp.startswith("["):
        host, _, rest = hp[1:].partition("]")
        if not rest.startswith(":") or not rest[1:].isdigit():
            raise ValueError(f"нет порта: '{hp}'")
        return host, int(rest[1:])
    host, _, p = hp.rpartition(":")
    if not host or not p.isdigit() or not (1 <= int(p) <= 65535):
        raise ValueError(f"ожидался host:port, получено '{hp}'")
    return host, int(p)


def _stream_settings(p: dict) -> "tuple[dict, list]":
    """Строит streamSettings из плоских параметров ссылки/мастера.

    Единый источник правды для парсеров ссылок и мастера: p = {type,
    headerType, host, path, serviceName, multiMode, mode, security, sni,
    alpn, fp, allowInsecure, pbk, sid, spx, seed, key, quicSecurity}.
    Возвращает (streamSettings|None, warnings).
    """
    w = []
    net = (str(p.get("type") or p.get("net") or "tcp")).lower()
    if net == "raw":
        net = "tcp"                      # xray ≥24 принимает оба; канон узла — tcp
    sec = (str(p.get("security") or p.get("tls") or "")).lower()
    if sec in ("", "0", "false", "none"):
        sec = "none"

    ss: dict = {"network": net}

    if net == "tcp":
        ht = (str(p.get("headerType") or "none")).lower()
        if ht == "http":
            req = {"version": "1.1", "method": "GET",
                   "path": [str(p.get("path") or "/")], "headers": {}}
            host = str(p.get("host") or "").strip()
            if host:
                req["headers"]["Host"] = [host]
            ss["tcpSettings"] = {"header": {"type": "http", "request": req}}
    elif net == "ws":
        ws = {"path": str(p.get("path") or "/")}
        host = str(p.get("host") or "").strip()
        if host:
            ws["headers"] = {"Host": host}
        ss["wsSettings"] = ws
    elif net in ("grpc", "gun"):
        grpc = {"serviceName": str(p.get("serviceName") or p.get("path") or ""),
                "multiMode": str(p.get("multiMode") or "0") == "1"}
        auth = str(p.get("authority") or p.get("host") or "").strip()
        if auth:
            grpc["authority"] = auth
        ss["network"] = "grpc"
        ss["grpcSettings"] = grpc
    elif net == "httpupgrade":
        hu = {"path": str(p.get("path") or "/")}
        host = str(p.get("host") or "").strip()
        if host:
            hu["host"] = host
        ss["httpupgradeSettings"] = hu
    elif net == "xhttp":
        xh = {"path": str(p.get("path") or "/")}
        host = str(p.get("host") or "").strip()
        if host:
            xh["host"] = host
        if p.get("mode"):
            xh["mode"] = str(p.get("mode"))
        ss["xhttpSettings"] = xh
    elif net in ("kcp", "mkcp"):
        kcp = {"mtu": 1350, "tti": 50, "uplinkCapacity": 12,
               "downlinkCapacity": 100, "congestion": False,
               "readBufferSize": 2, "writeBufferSize": 2,
               "header": {"type": str(p.get("headerType") or "none")}}
        if p.get("seed"):
            kcp["seed"] = str(p.get("seed"))
        ss["network"] = "mkcp"
        ss["kcpSettings"] = kcp
    elif net == "quic":
        ss["quicSettings"] = {
            "security": str(p.get("quicSecurity") or "none"),
            "key": str(p.get("key") or ""),
            "header": {"type": str(p.get("headerType") or "none")}}
    elif net == "http":
        h2 = {"path": str(p.get("path") or "/")}
        hosts = str(p.get("host") or "").strip()
        if hosts:
            h2["host"] = [h.strip() for h in hosts.split(",") if h.strip()]
        ss["httpSettings"] = h2
    else:
        w.append(f"Неизвестный транспорт '{net}' — использую tcp")
        ss["network"] = "tcp"

    if sec == "reality":
        rs = {"show": False,
              "fingerprint": str(p.get("fp") or "chrome"),
              "serverName": str(p.get("sni") or p.get("host") or ""),
              "publicKey": str(p.get("pbk") or ""),
              "shortId": str(p.get("sid") or ""),
              "spiderX": str(p.get("spx") or "/")}
        if not rs["serverName"]:
            w.append("REALITY без SNI — Xray может отклонить конфиг")
        if not rs["publicKey"]:
            w.append("REALITY без publicKey (pbk) — Xray отклонит конфиг")
        ss["security"] = "reality"
        ss["realitySettings"] = rs
    elif sec == "tls":
        ts: dict = {"serverName": str(p.get("sni") or p.get("host") or "")}
        alpn = str(p.get("alpn") or "").strip()
        if alpn:
            ts["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        if p.get("fp"):
            ts["fingerprint"] = str(p.get("fp"))
        if str(p.get("allowInsecure") or p.get("insecure") or "0") in ("1", "true", "yes"):
            ts["allowInsecure"] = True
        ss["security"] = "tls"
        ss["tlsSettings"] = ts
    else:
        ss["security"] = "none"

    return ss, w


def _parse_vless(link: str) -> dict:
    pr = urlparse(link)
    if not pr.username:
        raise ValueError("vless:// — нет UUID перед @")
    try:
        host, port = pr.hostname, pr.port
    except ValueError as ex:
        raise ValueError(f"vless:// — плохой host:port: {ex}")
    if not host or not port:
        raise ValueError("vless:// — нет host:port")
    q = {k: (v[0] if v else "") for k, v in parse_qs(pr.query).items()}
    enc = (q.get("encryption") or "none").strip()
    if enc == "auto":
        enc = "none"
    user: dict = {"id": unquote(pr.username).strip(), "encryption": enc}
    flow = (q.get("flow") or "").strip()
    if flow:
        user["flow"] = flow
    settings = {"vnext": [{"address": host, "port": int(port), "users": [user]}]}
    stream, w = _stream_settings(q)
    if stream.get("security") == "reality":
        rs = stream["realitySettings"]
        if not rs.get("serverName"):
            rs["serverName"] = host
    return {"protocol": "vless", "settings": settings,
            "streamSettings": stream,
            "suggested": unquote(pr.fragment).strip() if pr.fragment else "",
            "warnings": w}


def _parse_vmess(link: str) -> dict:
    body = link[len("vmess://"):].strip()
    raw: bytes
    if body.startswith("{"):
        raw = body.encode("utf-8")
    else:
        try:
            raw = _b64_decode(body)
        except ValueError as ex:
            raise ValueError(f"vmess:// — {ex}")
    try:
        obj = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        raise ValueError("vmess:// — base64 раскодирован, но внутри не JSON")
    if not isinstance(obj, dict) or not obj.get("add"):
        raise ValueError("vmess:// — в JSON нет адреса (add)")
    try:
        port = int(obj.get("port") or 0)
    except (TypeError, ValueError):
        raise ValueError(f"vmess:// — плохой порт: {obj.get('port')}")
    if not (1 <= port <= 65535):
        raise ValueError(f"vmess:// — порт вне диапазона: {port}")
    user = {"id": str(obj.get("id") or ""),
            "alterId": int(obj.get("aid") or obj.get("alterId") or 0),
            "security": str(obj.get("scy") or "auto")}
    settings = {"vnext": [{"address": str(obj["add"]), "port": port,
                           "users": [user]}]}
    p = {"type": obj.get("net"), "headerType": obj.get("type"),
         "host": obj.get("host"), "path": obj.get("path"),
         "security": obj.get("tls"), "sni": obj.get("sni"),
         "alpn": obj.get("alpn"), "fp": obj.get("fp")}
    if str(obj.get("tls") or "").lower() == "reality" or obj.get("pbk"):
        p["security"] = "reality"
        p["pbk"], p["sid"], p["spx"] = obj.get("pbk"), obj.get("sid"), obj.get("spx")
    stream, w = _stream_settings(p)
    if stream.get("security") == "reality":
        rs = stream["realitySettings"]
        if not rs.get("serverName"):
            rs["serverName"] = str(obj.get("sni") or obj.get("add") or "")
    return {"protocol": "vmess", "settings": settings,
            "streamSettings": stream,
            "suggested": str(obj.get("ps") or "").strip(),
            "warnings": w}


def _parse_trojan(link: str) -> dict:
    pr = urlparse(link)
    if not pr.username:
        raise ValueError("trojan:// — нет пароля перед @")
    try:
        host, port = pr.hostname, pr.port
    except ValueError as ex:
        raise ValueError(f"trojan:// — плохой host:port: {ex}")
    if not host or not port:
        raise ValueError("trojan:// — нет host:port")
    q = {k: (v[0] if v else "") for k, v in parse_qs(pr.query).items()}
    if not q.get("security"):
        q["security"] = "tls"           # trojan без явного security = TLS
    settings = {"servers": [{"address": host, "port": int(port),
                             "password": unquote(pr.username)}]}
    stream, w = _stream_settings(q)
    if stream.get("security") == "tls":
        ts = stream["tlsSettings"]
        if not ts.get("serverName"):
            ts["serverName"] = host
    return {"protocol": "trojan", "settings": settings,
            "streamSettings": stream,
            "suggested": unquote(pr.fragment).strip() if pr.fragment else "",
            "warnings": w}


def _parse_ss(link: str) -> dict:
    body = link[len("ss://"):]
    suggested = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        suggested = unquote(frag).strip()
    q: dict = {}
    if "?" in body:
        body, qs = body.split("?", 1)
        q = {k: (v[0] if v else "") for k, v in parse_qs(qs).items()}

    method = pw = ""
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        # SIP002: plain-userinfo ВСЕГДА содержит ":" (method:password),
        # base64url-userinfo НИКОГДА (алфавит b64) — различаем по нему.
        if ":" in userinfo:
            method, pw = userinfo.split(":", 1)
        else:
            try:
                dec = _b64_decode(userinfo).decode("utf-8", "replace")
            except ValueError as ex:
                raise ValueError(f"ss:// — {ex}")
            if ":" not in dec:
                raise ValueError("ss:// — нет метода:пароль")
            method, pw = dec.split(":", 1)
    else:
        # legacy: всё тело — base64(method:password@host:port)
        try:
            dec = _b64_decode(body).decode("utf-8", "replace")
        except ValueError as ex:
            raise ValueError(f"ss:// — {ex}")
        if "@" not in dec:
            raise ValueError("ss:// — legacy-base64 без @host:port")
        userinfo, hostport = dec.rsplit("@", 1)
        if ":" in userinfo:
            method, pw = userinfo.split(":", 1)

    host, port = _split_hostport(hostport)
    if not method:
        raise ValueError("ss:// — не удалось разобрать метод шифрования")
    settings = {"servers": [{"address": host, "port": port,
                             "method": method, "password": pw}]}
    w = []
    if q.get("plugin"):
        w.append(f"SIP003-плагин '{q['plugin']}' не поддерживается Xray — "
                 f"добавлено без плагина")
    return {"protocol": "shadowsocks", "settings": settings,
            "streamSettings": None, "suggested": suggested, "warnings": w}


def _parse_json_outbound(text: str) -> dict:
    """Готовый JSON outbound (однострочный, v2rayN/Xray-формат)."""
    try:
        obj = json.loads(text.strip())
    except Exception as ex:
        raise ValueError(f"JSON не разобран: {ex}")
    if not isinstance(obj, dict):
        raise ValueError("JSON outbound — должен быть один объект {…}")
    if "outbounds" in obj and "protocol" not in obj:
        raise ValueError("Это ПОЛНЫЙ конфиг (с outbounds[]) — нужен один "
                         "объект outbound")
    if not obj.get("protocol"):
        raise ValueError("JSON без поля protocol")
    suggested = str(obj.pop("tag", "") or "")
    w = []
    if obj["protocol"] in ("vless", "vmess", "trojan", "shadowsocks",
                           "socks", "http") and not obj.get("settings"):
        w.append(f"protocol {obj['protocol']} без settings — проверьте JSON")
    return {"protocol": obj["protocol"], "settings": obj.get("settings") or {},
            "streamSettings": obj.get("streamSettings"),
            "suggested": suggested, "warnings": w,
            "extra": {k: v for k, v in obj.items()
                      if k not in ("protocol", "settings", "streamSettings")}}


def parse_share_link(link: str) -> dict:
    """Диспетчер: vless:// vmess:// trojan:// ss:// → части outbound."""
    link = link.strip()
    low = link.lower()
    if low.startswith("vless://"):
        return _parse_vless(link)
    if low.startswith("vmess://"):
        return _parse_vmess(link)
    if low.startswith("trojan://"):
        return _parse_trojan(link)
    if low.startswith("ss://"):
        return _parse_ss(link)
    raise ValueError("Неизвестная схема — поддерживаются vless:// vmess:// "
                     "trojan:// ss://")


# ══════════════════════════════════════════════════════════════════════════════
#  ВАЛИДАТОРЫ (для TuiField)
# ══════════════════════════════════════════════════════════════════════════════

def _co_v_host(text: str) -> "str | None":
    t = text.strip()
    if not t:
        return "Введите адрес (домен или IP)"
    h = t.strip("[]")
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$', t) and "." in t:
        return None
    return f"'{t}' — не домен и не IP"


def _co_v_port(text: str) -> "str | None":
    t = text.strip()
    if not t.isdigit() or not (1 <= int(t) <= 65535):
        return "Порт: целое 1-65535"
    return None


def _co_v_uuid(text: str) -> "str | None":
    t = text.strip()
    if not t:
        return "Введите UUID"
    try:
        _uuid_mod.UUID(t)
        return None
    except ValueError:
        return "UUID вида 3b7c1f44-8f66-4b45-9d5a-1e2f3a4b5c6d (36 симв.)"


def _co_v_tag(text: str) -> "str | None":
    t = text.strip().lower()
    if not t:
        return "Введите тег outbound"
    if not CO_TAG_RE.match(t):
        return "Тег: 2-64 символа, a-z0-9._-, начинается с буквы/цифры"
    return None


def _co_v_int(lo: int, hi: int, label: str = "число"):
    def _v(text: str) -> "str | None":
        t = text.strip()
        if not t:
            return None
        if not t.isdigit() or not (lo <= int(t) <= hi):
            return f"{label}: целое {lo}-{hi}"
        return None
    return _v


def _co_v_required(label: str):
    def _v(text: str) -> "str | None":
        return None if text.strip() else f"Введите {label}"
    return _v


# ══════════════════════════════════════════════════════════════════════════════
#  ОПИСАНИЕ / РАЗБОР OUTBOUND (для сводок и префилла мастера)
# ══════════════════════════════════════════════════════════════════════════════

def _co_target(ob_or_parts: dict) -> "tuple":
    """(address, port) из settings-структуры (полный outbound или parts)."""
    s = (ob_or_parts or {}).get("settings") or {}
    if isinstance(s.get("vnext"), list) and s["vnext"]:
        v = s["vnext"][0] or {}
        return v.get("address", "?"), v.get("port", "?")
    if isinstance(s.get("servers"), list) and s["servers"]:
        v = s["servers"][0] or {}
        return v.get("address", "?"), v.get("port", "?")
    return "?", "?"


def _co_mask(secret: str, keep: int = 4) -> str:
    s = str(secret or "")
    if len(s) <= keep * 2:
        return "•" * len(s)
    return f"{s[:keep]}…{s[-keep:]}"


def _co_describe(entry: dict) -> str:
    """Короткая сводка для списка: 'vless  1.2.3.4:443  tcp/reality'."""
    ob    = entry.get("outbound", {}) or {}
    proto = ob.get("protocol", "?")
    addr, port = _co_target(ob)
    ss    = ob.get("streamSettings") or {}
    net   = ss.get("network", "tcp")
    sec   = ss.get("security", "none")
    return f"{proto}  {addr}:{port}  {net}/{sec}"


def _co_extract_spec(ob: dict) -> dict:
    """Полный outbound → плоские дефолты для префилла мастера (замена)."""
    spec: dict = {}
    proto = ob.get("protocol", "")
    s = ob.get("settings", {}) or {}
    if isinstance(s.get("vnext"), list) and s["vnext"]:
        v = s["vnext"][0] or {}
        u = ((v.get("users") or [{}]) or [{}])[0] or {}
        spec.update(address=v.get("address", ""), port=str(v.get("port", "")),
                    uuid=u.get("id", ""), flow=u.get("flow", ""),
                    alterId=str(u.get("alterId", 0)),
                    vmsec=u.get("security", "auto"))
    elif isinstance(s.get("servers"), list) and s["servers"]:
        v = s["servers"][0] or {}
        u = ((v.get("users") or [{}]) or [{}])[0] or {}
        spec.update(address=v.get("address", ""), port=str(v.get("port", "")),
                    password=v.get("password", "") or u.get("pass", ""),
                    method=v.get("method", ""), user=u.get("user", ""))
    ss = ob.get("streamSettings") or {}
    net = ss.get("network", "tcp")
    spec["network"] = net
    spec["security"] = ss.get("security", "none")
    if net == "tcp":
        hdr = ((ss.get("tcpSettings") or {}).get("header") or {})
        spec["headerType"] = hdr.get("type", "none")
        req = hdr.get("request") or {}
        if req.get("path"):
            spec["path"] = req["path"][0]
        hosts = (req.get("headers") or {}).get("Host")
        if hosts:
            spec["host"] = hosts[0]
    elif net == "ws":
        w = ss.get("wsSettings") or {}
        spec["path"] = w.get("path", "/")
        spec["host"] = (w.get("headers") or {}).get("Host", "")
    elif net == "grpc":
        g = ss.get("grpcSettings") or {}
        spec["serviceName"] = g.get("serviceName", "")
        spec["host"] = g.get("authority", "")
        spec["multiMode"] = "1" if g.get("multiMode") else "0"
    elif net == "httpupgrade":
        h = ss.get("httpupgradeSettings") or {}
        spec["path"] = h.get("path", "/")
        spec["host"] = h.get("host", "")
    elif net == "xhttp":
        x = ss.get("xhttpSettings") or {}
        spec["path"] = x.get("path", "/")
        spec["host"] = x.get("host", "")
        spec["mode"] = x.get("mode", "auto")
    sec = ss.get("security")
    if sec == "tls":
        t = ss.get("tlsSettings") or {}
        spec["sni"] = t.get("serverName", "")
        spec["alpn"] = ",".join(t.get("alpn") or [])
        spec["fp"] = t.get("fingerprint", "")
        spec["allowInsecure"] = "1" if t.get("allowInsecure") else "0"
    elif sec == "reality":
        r = ss.get("realitySettings") or {}
        spec["sni"] = r.get("serverName", "")
        spec["fp"] = r.get("fingerprint", "chrome")
        spec["pbk"] = r.get("publicKey", "")
        spec["sid"] = r.get("shortId", "")
        spec["spx"] = r.get("spiderX", "/")
    return spec


def _co_suggest_tag(raw: str, protocol: str, target: "tuple") -> str:
    """Имя ссылки → допустимый тег: 'Друг YYY' → 'yyy' (латиница выживает),
    'Друг' → 'vless-1.2.3.4' (нет латиницы — от протокола и адреса)."""
    base = (raw or "").strip().lower()
    base = re.sub(r'[^a-z0-9._-]+', '-', base).strip("-.")
    if len(base) < 2 and target and target[0] and target[0] != "?":
        base = re.sub(r'[^a-z0-9._-]+', '-',
                      f"{protocol}-{target[0]}".lower()).strip("-.")
    if len(base) < 2:
        base = f"custom-{protocol}"
    if not base[0].isalnum():
        base = "n" + base
    return base[:64]


# ══════════════════════════════════════════════════════════════════════════════
#  МАСТЕР (форма по протоколу → settings + streamSettings)
# ══════════════════════════════════════════════════════════════════════════════

def _co_settings_from_form(protocol: str, f: dict, flow: str = "",
                            method: str = "", vmsec: str = "auto") -> dict:
    addr = f["address"].strip()
    port = int(f["port"])
    if protocol == "vless":
        user = {"id": f["uuid"].strip(), "encryption": "none"}
        if flow:
            user["flow"] = flow
        return {"vnext": [{"address": addr, "port": port, "users": [user]}]}
    if protocol == "vmess":
        user = {"id": f["uuid"].strip(),
                "alterId": int(f.get("alterId") or 0),
                "security": vmsec or "auto"}
        return {"vnext": [{"address": addr, "port": port, "users": [user]}]}
    if protocol == "trojan":
        return {"servers": [{"address": addr, "port": port,
                             "password": f["password"]}]}
    if protocol == "shadowsocks":
        return {"servers": [{"address": addr, "port": port,
                             "method": method, "password": f["password"]}]}
    # socks / http
    srv: dict = {"address": addr, "port": port}
    if (f.get("user") or "").strip():
        srv["users"] = [{"user": f["user"].strip(), "pass": f.get("pass", "")}]
    return {"servers": [srv]}


def _co_wizard(protocol: str, spec: "dict | None" = None) -> "tuple | None":
    """Мастер: формы → (settings, streamSettings, warnings) или None.

    spec — префилл при замене существующего outbound (_co_extract_spec).
    """
    spec = spec or {}
    d = lambda k, dv="": str(spec.get(k, dv) or dv or "")

    # ── Форма 1: сервер + креды ──
    fields = [
        TuiField(key="address", label="Адрес", default=d("address"),
                 required=True, validator=_co_v_host,
                 hint="домен или IP сервера (напр. сервер друга)"),
        TuiField(key="port", label="Порт", default=d("port", "443"),
                 required=True, validator=_co_v_port),
    ]
    if protocol in ("vless", "vmess"):
        fields.append(TuiField(key="uuid", label="UUID",
                               default=d("uuid"), required=True,
                               validator=_co_v_uuid,
                               hint="выдаёт владелец сервера"))
    if protocol == "vmess":
        fields.append(TuiField(key="alterId", label="alterId",
                               default=d("alterId", "0"),
                               validator=_co_v_int(0, 65535, "alterId"),
                               hint="современные серверы: 0"))
    if protocol in ("trojan", "shadowsocks"):
        fields.append(TuiField(key="password", label="Пароль",
                               default=d("password"), required=True,
                               secret=True))
    if protocol in ("socks", "http"):
        fields += [
            TuiField(key="user", label="Юзер (опц.)", default=d("user")),
            TuiField(key="pass", label="Пароль (опц.)", default=d("password"),
                     secret=True),
        ]
    f1 = tui_form(f"Outbound {protocol} — сервер", fields)
    if not f1:
        return None

    method, flow, vmsec = "chacha20-ietf-poly1305", "", "auto"
    if protocol == "shadowsocks":
        try:
            pre = list(CO_METHODS).index(d("method"))
        except ValueError:
            pre = 0
        mi = tui_select("Метод шифрования", list(CO_METHODS), default=pre)
        if mi is None:
            return None
        method = CO_METHODS[mi]
    if protocol == "vless":
        fi = tui_select("Flow (XTLS)", ["— без flow —", "xtls-rprx-vision"],
                        default=1 if d("flow") == "xtls-rprx-vision" else 0)
        if fi is None:
            return None
        flow = "xtls-rprx-vision" if fi == 1 else ""
    if protocol == "vmess":
        secs = ["auto", "none", "aes-128-gcm", "chacha20-poly1305", "zero"]
        try:
            pre = secs.index(d("vmsec", "auto"))
        except ValueError:
            pre = 0
        si = tui_select("Шифрование payload (security)", secs, default=pre)
        if si is None:
            return None
        vmsec = secs[si]

    # ── Транспорт ──
    try:
        pre = list(CO_NETWORKS).index(d("network", "tcp"))
    except ValueError:
        pre = 0
    ni = tui_select("Транспорт (network)", list(CO_NETWORKS), default=pre)
    if ni is None:
        return None
    network = CO_NETWORKS[ni]
    p: dict = {"type": network, "security": "none"}

    if network == "tcp":
        hts = ["none", "http"]
        hi = tui_select("TCP header (маскировка)", hts,
                        default=1 if d("headerType") == "http" else 0)
        if hi is None:
            return None
        p["headerType"] = hts[hi]
        if hts[hi] == "http":
            fh = tui_form("TCP http header", [
                TuiField(key="path", label="Path", default=d("path", "/"),
                         required=True),
                TuiField(key="host", label="Host", default=d("host"),
                         hint="напр. www.example.com"),
            ])
            if not fh:
                return None
            p["path"], p["host"] = fh["path"], fh["host"]
    elif network == "ws":
        fh = tui_form("WebSocket", [
            TuiField(key="path", label="Path", default=d("path", "/"),
                     required=True),
            TuiField(key="host", label="Host (опц.)", default=d("host")),
        ])
        if not fh:
            return None
        p["path"], p["host"] = fh["path"], fh["host"]
    elif network == "grpc":
        fg = tui_form("gRPC", [
            TuiField(key="serviceName", label="serviceName",
                     default=d("serviceName"), required=True),
            TuiField(key="host", label="authority (опц.)", default=d("host")),
        ])
        if not fg:
            return None
        p["serviceName"], p["host"] = fg["serviceName"], fg["host"]
        mm = tui_select("multiMode", ["нет (поток)", "да (пакеты)"],
                        default=1 if d("multiMode") == "1" else 0)
        if mm is None:
            return None
        p["multiMode"] = "1" if mm == 1 else "0"
    elif network == "httpupgrade":
        fh = tui_form("HTTPUpgrade", [
            TuiField(key="path", label="Path", default=d("path", "/"),
                     required=True),
            TuiField(key="host", label="Host (опц.)", default=d("host")),
        ])
        if not fh:
            return None
        p["path"], p["host"] = fh["path"], fh["host"]
    elif network == "xhttp":
        fh = tui_form("XHTTP", [
            TuiField(key="path", label="Path", default=d("path", "/"),
                     required=True),
            TuiField(key="host", label="Host (опц.)", default=d("host")),
        ])
        if not fh:
            return None
        p["path"], p["host"] = fh["path"], fh["host"]
        modes = ["auto", "stream", "packet"]
        try:
            pre = modes.index(d("mode", "auto"))
        except ValueError:
            pre = 0
        mi = tui_select("Режим XHTTP", modes, default=pre)
        if mi is None:
            return None
        p["mode"] = modes[mi]

    # ── Security ──
    secs = ["none", "tls", "reality"]
    try:
        pre = secs.index(d("security", "none"))
    except ValueError:
        pre = 0
    if not pre and protocol == "trojan":
        pre = 1                     # trojan обычно по TLS
    si = tui_select("Шифрование канала (security)", secs, default=pre)
    if si is None:
        return None
    p["security"] = secs[si]

    if secs[si] == "tls":
        ft = tui_form("TLS", [
            TuiField(key="sni", label="SNI", default=d("sni") or f1["address"],
                     hint="пусто/адрес = сервер сам подставит"),
            TuiField(key="alpn", label="ALPN (опц.)", default=d("alpn"),
                     hint="напр. h2,http/1.1"),
        ])
        if not ft:
            return None
        fps = ["—"] + list(CO_FPS)
        try:
            fpre = fps.index(d("fp")) if d("fp") else 0
        except ValueError:
            fpre = 0
        fi = tui_select("uTLS fingerprint (маскировка клиента)", fps,
                        default=fpre)
        if fi is None:
            return None
        ai = tui_confirm("allowInsecure (самоподписанный сертификат)?",
                         default=False)
        p.update(sni=ft["sni"], alpn=ft["alpn"],
                 fp=fps[fi] if fi else "",
                 allowInsecure="1" if ai else "0")
    elif secs[si] == "reality":
        fr = tui_form("REALITY", [
            TuiField(key="sni", label="SNI (serverName)",
                     default=d("sni") or f1["address"], required=True,
                     hint="домен-маскировка сервера"),
            TuiField(key="pbk", label="publicKey (pbk)", default=d("pbk"),
                     required=True, hint="выдаёт владелец сервера"),
            TuiField(key="sid", label="shortId (опц.)", default=d("sid")),
            TuiField(key="spx", label="spiderX", default=d("spx", "/"),
                     hint="обычно /"),
        ])
        if not fr:
            return None
        try:
            fpre = list(CO_FPS).index(d("fp", "chrome"))
        except ValueError:
            fpre = 0
        fi = tui_select("uTLS fingerprint", list(CO_FPS), default=fpre)
        if fi is None:
            return None
        p.update(fr, fp=CO_FPS[fi])

    stream, warns = _stream_settings(p)
    settings = _co_settings_from_form(protocol, f1, flow, method, vmsec)
    return settings, stream, warns


# ══════════════════════════════════════════════════════════════════════════════
#  ПРЕВЬЮ + ТЕГ
# ══════════════════════════════════════════════════════════════════════════════

def _co_preview(tag: str, parts: dict, warnings: list,
                replace_name: "str | None" = None) -> bool:
    """Сводка outbound'а + подтверждение. True = создавать."""
    proto = parts.get("protocol", "?")
    settings = parts.get("settings") or {}
    stream = parts.get("streamSettings") or {}
    addr, port = _co_target(parts)

    print()
    _box_top(f"{'Замена' if replace_name else 'Новый'} outbound: {tag}")
    _box_kv("Протокол", proto)
    _box_kv("Адрес", f"{addr}:{port}")
    if proto in ("vless", "vmess"):
        u = ((settings.get("vnext") or [{}])[0].get("users") or [{}])[0]
        _box_kv("UUID", _co_mask(u.get("id", ""), 6))
        if u.get("flow"):
            _box_kv("Flow", u["flow"])
        if proto == "vmess":
            _box_kv("alterId/security",
                    f"{u.get('alterId', 0)} / {u.get('security', 'auto')}")
    elif proto in ("trojan", "shadowsocks"):
        srv = (settings.get("servers") or [{}])[0]
        if proto == "shadowsocks":
            _box_kv("Метод", srv.get("method", "?"))
        _box_kv("Пароль", _co_mask(srv.get("password", ""), 3))
    elif proto in ("socks", "http"):
        srv = (settings.get("servers") or [{}])[0]
        if srv.get("users"):
            _box_kv("Авторизация", f"{srv['users'][0].get('user', '')} / •••")
    if stream:
        _box_kv("Транспорт", stream.get("network", "tcp"))
        _box_kv("Security", stream.get("security", "none"))
        sec_s = stream.get("security")
        if sec_s == "reality":
            rs = stream.get("realitySettings") or {}
            _box_kv("  SNI", rs.get("serverName", ""))
            _box_kv("  pbk", _co_mask(rs.get("publicKey", ""), 8))
            _box_kv("  fp", rs.get("fingerprint", "chrome"))
        elif sec_s == "tls":
            ts = stream.get("tlsSettings") or {}
            _box_kv("  SNI", ts.get("serverName", "") or "—")
            if ts.get("alpn"):
                _box_kv("  ALPN", ",".join(ts["alpn"]))
            if ts.get("allowInsecure"):
                _box_kv("  allowInsecure", "да")
        net = stream.get("network")
        if net == "ws":
            ws = stream.get("wsSettings") or {}
            _box_kv("  path", ws.get("path", "/"))
        elif net == "grpc":
            g = stream.get("grpcSettings") or {}
            _box_kv("  serviceName", g.get("serviceName", ""))
    if parts.get("extra"):
        _box_kv("Доп. поля", ", ".join(sorted(parts["extra"].keys())))
    if warnings:
        _box_sep()
        for wmsg in warnings:
            _box_warn(f"  ⚠ {wmsg}")
    _box_row()
    _box_desc("Outbound добавляется в КОНЕЦ outbounds[] — дефолтный outbound")
    _box_desc("не меняется; без routing-правила на этот тег трафик туда не идёт.")
    _box_bottom()
    return tui_confirm("Создать и применить к Xray (рестарт)?", default=True)


def _co_pick_tag(default_tag: str, replace: "str | None" = None) -> "str | None":
    """Тег outbound: форма + проверка занятости. None = отмена."""
    live  = _co_live_tags() - ({replace} if replace else set())
    names = {e.get("name") for e in _co_load().get("outbounds", [])
             if e.get("name") != replace}
    while True:
        res = tui_form("Тег outbound", [
            TuiField(key="tag", label="Тег", default=default_tag,
                     required=True, validator=_co_v_tag,
                     hint="a-z0-9._- ; станет тегом outbound в конфиге Xray"),
        ])
        if not res:
            return None
        tag = res["tag"].strip().lower()
        if tag in live or tag in names:
            _warn(f"Тег '{tag}' уже занят — выберите другой")
            continue
        return tag


# ══════════════════════════════════════════════════════════════════════════════
#  ПРОВЕРКИ
# ══════════════════════════════════════════════════════════════════════════════

def _co_refs_in_routing(tag: str) -> list:
    """Живые routing-правила, ссылающиеся на тег (для warn при удалении)."""
    refs = []
    for _p, cfg in _co_iter_configs():
        for r in cfg.get("routing", {}).get("rules", []):
            if r.get("outboundTag") == tag:
                label = r.get("comment") or ", ".join(
                    (r.get("domain") or r.get("ip") or ["—"])[:2])
                refs.append(str(label)[:48])
    seen, out = set(), []
    for r in refs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _co_tcp_check(entry: dict) -> None:
    addr, port = _co_target(entry.get("outbound", {}))
    print()
    _box_top(f"TCP-проверка: {entry.get('name', '?')}")
    _box_kv("Цель", f"{addr}:{port}")
    _box_row()
    if addr == "?":
        _box_warn("  Не удалось определить адрес (нет vnext/servers)")
        _box_bottom()
        return
    t0 = time.time()
    try:
        with socket.create_connection((str(addr), int(port)), timeout=6):
            ms = (time.time() - t0) * 1000
        _box_ok(f"  ✅ Хост отвечает (TCP connect, {ms:.0f} мс)")
        _box_row()
        _box_desc("Отвечает ли TCP-порт. Протокол/UUID/REALITY-ключи этим не")
        _box_desc("проверяются — только реальным трафиком через правило.")
    except Exception as ex:
        _box_warn(f"  ❌ {ex.__class__.__name__}: {ex}")
        _box_row()
        _box_desc("Недоступен ≠ неверный outbound: сервер друга может быть")
        _box_desc("выключен или фильтровать IP этой ноды.")
    _box_bottom()


# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНЫЙ FLOW СОЗДАНИЯ / ЗАМЕНЫ
# ══════════════════════════════════════════════════════════════════════════════

def _co_paste(prompt: str, hint: str = "") -> str:
    """Вставка длинной строки (ссылка/JSON) — cooked input, без TUI-буферов:
    вставка в tui_form рендерила бы экран на каждый символ ссылки."""
    print()
    _box_top(prompt)
    _box_row()
    if hint:
        _box_desc(hint)
    _box_bottom()
    try:
        return input(f"  {CYAN}>{NC} ").strip()
    except (KeyboardInterrupt, EOFError):
        return ""


def _co_add_flow(replace: "dict | None" = None) -> "dict | None":
    """Интерактивное создание (replace=None) / замена определения outbound.

    Возвращает entry, УЖЕ сохранённую в state и применённую к конфигу
    (валидация + рестарт), или None (отмена/ошибка — state откачен).
    """
    replace_name = (replace or {}).get("name")
    spec = _co_extract_spec(replace["outbound"]) if replace else {}

    if replace:
        print()
        _box_top(f"Замена outbound: {replace_name}")
        _box_row()
        _box_desc(f"Сейчас: {_co_describe(replace)}")
        _box_desc("Новое определение заменит старое; тег можно оставить.")
        _box_bottom()

    methods = [
        "Импорт ссылки   vless://  vmess://  trojan://  ss://",
        "Мастер          форма по протоколу (vless/vmess/trojan/ss/socks/http)",
        "Готовый JSON    однострочный outbound (v2rayN / Xray-формат)",
    ]
    mdef = 0
    if replace and replace.get("source") in ("link", "wizard", "json"):
        mdef = ("link", "wizard", "json").index(replace["source"])
    mi = tui_select("Способ создания", methods, default=mdef)
    if mi is None:
        return None

    parts: "dict | None" = None
    warnings: list = []
    suggested = replace_name or ""

    if mi == 0:
        raw = _co_paste("Импорт по ссылке",
                        "Вставьте ссылку (vless:// vmess:// trojan:// ss://) "
                        "и нажмите Enter; Esc-строки не нужны")
        if not raw:
            return None
        try:
            parts = parse_share_link(raw)
        except ValueError as ex:
            _warn(str(ex))
            return None
        warnings  = parts.get("warnings", [])
        suggested = parts.get("suggested", "") or suggested
    elif mi == 1:
        pre = 0
        if replace and spec:
            try:
                pre = list(CO_PROTOCOLS).index(replace["outbound"].get("protocol", ""))
            except ValueError:
                pre = 0
        pi = tui_select("Протокол", list(CO_PROTOCOLS), default=pre)
        if pi is None:
            return None
        res = _co_wizard(CO_PROTOCOLS[pi], spec)
        if not res:
            return None
        settings, stream, warnings = res
        parts = {"protocol": CO_PROTOCOLS[pi], "settings": settings,
                 "streamSettings": stream}
    else:
        raw = _co_paste("Готовый JSON outbound",
                        'Одна строка: {"protocol":"vless","settings":{…}} — '
                        'тег зададим отдельно')
        if not raw:
            return None
        try:
            parts = _parse_json_outbound(raw)
        except ValueError as ex:
            _warn(str(ex))
            return None
        warnings  = parts.get("warnings", [])
        suggested = parts.get("suggested", "") or suggested

    # ── Тег ──
    default_tag = _co_suggest_tag(suggested, parts["protocol"], _co_target(parts))
    tag = _co_pick_tag(default_tag, replace=replace_name)
    if not tag:
        return None

    # ── Превью + подтверждение ──
    if not _co_preview(tag, parts, warnings, replace_name):
        return None

    # ── State + apply (с откатом state при отказе Xray) ──
    outbound = {"protocol": parts["protocol"],
                "settings": parts.get("settings") or {}}
    if parts.get("streamSettings"):
        outbound["streamSettings"] = parts["streamSettings"]
    for k, v in (parts.get("extra") or {}).items():
        outbound[k] = v

    entry = {
        "name": tag,
        "enabled": True,
        "source": ("link", "wizard", "json")[mi],
        "outbound": outbound,
        "created_at": (replace or {}).get("created_at") or _co_now(),
        "updated_at": _co_now(),
    }

    prev_state_text = CO_STATE_FILE.read_text() if CO_STATE_FILE.exists() else None
    state = _co_load()
    obs = state.setdefault("outbounds", [])
    if replace_name:
        state["outbounds"] = [entry if e.get("name") == replace_name else e
                              for e in obs]
    else:
        obs.append(entry)
    _co_save(state)

    if not _co_apply_to_xray(restart=True, validate=True):
        # Xray отказал — конфиг уже откачен _co_apply_to_xray; катим state
        if prev_state_text is not None:
            CO_STATE_FILE.write_text(prev_state_text)
        else:
            CO_STATE_FILE.unlink(missing_ok=True)
        _warn("Outbound НЕ сохранён — Xray отклонил конфиг (см. выше)")
        return None

    _log_change(f"outbound_{'edit' if replace_name else 'add'}:{tag}",
                f"{outbound['protocol']} → {_co_describe(entry)}")
    print()
    _success(f"Outbound '{tag}' {'заменён' if replace_name else 'создан'} и "
             f"применён к конфигу Xray")
    return entry


def co_create_outbound_inline() -> "str | None":
    """Для пикеров routing-правил: создать outbound «на ходу», вернуть тег.

    None = отмена (пользователь передумал или Xray отказал).
    """
    entry = _co_add_flow()
    return entry["name"] if entry else None


# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ УПРАВЛЕНИЯ
# ══════════════════════════════════════════════════════════════════════════════

def _co_pick_entry(prompt: str) -> "dict | None":
    entries = _co_load().get("outbounds", [])
    if not entries:
        _warn("Нет кастомных outbound'ов в state")
        return None
    pool = sorted(entries, key=lambda e: e.get("name", ""))
    options = []
    for e in pool:
        on = "●" if e.get("enabled", True) else "○"
        options.append(f"[{on}] {e.get('name', '?'):<26} {_co_describe(e)}")
    idx = tui_select(prompt, options)
    return pool[idx] if idx is not None else None


def _co_warn_refs(tag: str, action: str) -> bool:
    """Warn-бокс о routing-правилах, ссылающихся на тег. True = можно."""
    refs = _co_refs_in_routing(tag)
    if not refs:
        return True
    print()
    _box_top(f"⚠  На '{tag}' ссылаются routing-правила")
    _box_row()
    for r in refs[:6]:
        _box_row(f"  {CYAN}•{NC} {r}")
    if len(refs) > 6:
        _box_row(f"  {DIM}... ещё {len(refs) - 6}{NC}")
    _box_row()
    _box_warn(f"  После «{action}» трафик этих правил будет отбрасываться")
    _box_warn(f"  (outboundTag указывает в пустоту).")
    _box_bottom()
    return tui_confirm("Всё равно продолжить?", default=False)


def do_manage_custom_outbounds() -> None:
    """Меню управления кастомными outbound'ами."""
    while True:
        os.system("clear")
        state   = _co_load()
        entries = [e for e in state.get("outbounds", [])
                   if isinstance(e, dict) and e.get("name")]
        enabled = [e for e in entries if e.get("enabled", True)]
        live    = _co_live_tags()
        need    = {e["name"] for e in enabled}
        lost    = need - live

        print()
        _box_top("🔗  КАСТОМНЫЕ OUTBOUND'Ы")
        _box_row()
        _box_row(f"  {BOLD}Outbound'ов: {len(entries)}{NC}  "
                 f"{DIM}(включено {len(enabled)}, в конфиге {len(need & live)}){NC}")
        _box_desc("Свои ноды / серверы друзей — vless:// и не только; видны")
        _box_desc("во всех пикерах outbound (routing-правила, РФ-подсети).")
        if entries:
            _box_sep()
            shown = 0
            for e in sorted(entries, key=lambda x: x.get("name", "")):
                if shown >= 8:
                    _box_row(f"  {DIM}... ещё {len(entries) - 8}{NC}")
                    break
                shown += 1
                on   = e.get("enabled", True)
                dot  = f"{GREEN}●{NC}" if on else f"{DIM}○{NC}"
                name = e.get("name", "?")
                src  = CO_SRC_LABELS.get(e.get("source", ""), "")
                _box_row(f"  {dot} {CYAN}{name:<26}{NC} {_co_describe(e)}  "
                         f"{DIM}[{src}]{NC}")
        if lost:
            _box_sep()
            _box_row(f"  {RED}⚠  Потеряно в конфиге: {len(lost)}{NC}  "
                     f"{DIM}(regenerate стёр — пункт 5 восстановит){NC}")
        _box_row()
        _box_item("1", "Добавить outbound")
        _box_item("2", "Изменить (заменить определение)")
        _box_item("3", "Вкл / выкл")
        _box_item("4", "Удалить")
        _box_item("5", "Пере-применить все к конфигу (после regenerate)")
        _box_item("6", "Показать JSON")
        _box_item("7", "Проверить доступность (TCP)")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            _co_add_flow()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            target = _co_pick_entry("Какой outbound заменить?")
            if target:
                _co_add_flow(replace=target)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            _co_menu_toggle()
        elif ch == "4":
            _co_menu_delete()
        elif ch == "5":
            print()
            ok = _co_apply_to_xray(restart=True, validate=True)
            if ok:
                _success("Кастомные outbound'ы пере-применены")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            _co_menu_show()
        elif ch == "7":
            target = _co_pick_entry("Какой outbound проверить?")
            if target:
                _co_tcp_check(target)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", "0", ""):
            break
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _co_menu_toggle() -> None:
    target = _co_pick_entry("Какой outbound включить/выключить?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    name = target.get("name")
    turning_off = target.get("enabled", True)
    if turning_off and not _co_warn_refs(name, "выключить"):
        return
    state = _co_load()
    for e in state.get("outbounds", []):
        if e.get("name") == name:
            e["enabled"] = not e.get("enabled", True)
            e["updated_at"] = _co_now()
            new_val = e["enabled"]
            break
    else:
        return
    _co_save(state)
    _log_change(f"outbound_toggle:{name}", f"enabled={new_val}")
    _co_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _co_menu_delete() -> None:
    target = _co_pick_entry("Какой outbound удалить?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    name = target.get("name")
    if not _co_warn_refs(name, "удалить"):
        return
    if not tui_confirm(f"Удалить outbound '{name}' из state и конфига?",
                       default=False):
        return
    state = _co_load()
    state["outbounds"] = [e for e in state.get("outbounds", [])
                          if e.get("name") != name]
    _co_save(state)
    _log_change(f"outbound_del:{name}", "удалён")
    _co_apply_to_xray(restart=True, validate=True)
    _success(f"Outbound '{name}' удалён")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _co_menu_show() -> None:
    target = _co_pick_entry("JSON какого outbound показать?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    name = target.get("name", "?")
    try:
        js = json.dumps(target.get("outbound", {}), indent=2,
                        ensure_ascii=False)
    except Exception as ex:
        _warn(f"Не сериализуется: {ex}")
        return
    print()
    _box_top(f"JSON: {name}  (тег задаётся отдельно)")
    _box_row()
    for line in js.splitlines():
        _box_row(f"  {line}")
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")
