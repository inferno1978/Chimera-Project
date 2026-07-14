"""
chimera/modules/awg_rest_api.py
───────────────────────────────────────────────────────────────────────────────
HTTP-хендлеры для управления AmneziaWG-пирами (standalone-режим).

Встраивается в rest_api.py через awg_handle_get / awg_handle_post /
awg_handle_delete / awg_handle_patch. Делегирует авторизацию в
handler._require_admin() / handler._require_user() — НЕ дублирует логику
rate-limit / auth.

Модель доступа (см. задачу в промпте):
  • Админ управляет ВСЕМИ пирами без ограничений — создание, удаление,
    regen, изменение параметров, привязка/отвязка/переназначение пира к
    любому VLESS-пользователю (owner_email) в любой момент.
  • Обычный пользователь через user-портал видит и может действовать
    ТОЛЬКО на пира, у которого owner_email == его email: скачать конфиг,
    посмотреть QR, посмотреть свой трафик/expires, перевыпустить ключи.
    Ни привязку, ни удаление, ни чужих пиров — не может.
  • Пир БЕЗ owner_email — "технический"/неразобранный, виден только админу,
    в user-портале нигде не всплывает.

Все endpoints под /api/awg/. Если AWG не установлен (awgs_state_is_installed()
== False) — все endpoints отдают 404, а не 500.

Приватные ключи (client_privkey, server_privkey) НИКОГДА не попадают в
JSON-ответы — только в .conf-файл, который админ или владелец скачивает.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Ленивый импорт awg-модулей (как везде в проекте) ────────────────────────

def _awg_state():
    from . import awg_state
    return awg_state


def _awg_peers():
    from . import awg_peers
    return awg_peers


def _awg_apply():
    from . import awg_apply
    return awg_apply


def _awg_qr():
    from . import awg_qr
    return awg_qr


# ============================================================================
#  ВАЛИДАЦИЯ
# ============================================================================

def _is_awg_installed() -> bool:
    """Быстрая проверка: установлен ли standalone AWG."""
    try:
        return _awg_state().awgs_state_is_installed()
    except Exception:
        return False


def _validate_peer_name(name: str) -> bool:
    """
    Делегирует в awg_peers._validate_peer_name.
    Имя пира: 1-32 символа, [a-zA-Z0-9_-], не начинается с цифры.
    Это та же regex что в TUI — centralized валидация против path traversal.
    """
    try:
        return _awg_peers()._validate_peer_name(name)
    except Exception:
        return False


def _safe_peer_for_json(peer: dict) -> dict:
    """
    Возвращает копию пира без приватных ключей (для JSON-ответов API).

    Никогда не отдаём в JSON:
      • client_privkey  — приватный ключ клиента (Curve25519), даёт полный
                          доступ к туннелю от имени этого пира.
      • preshared_key   — PresharedKey (PSK), дополнительный симметричный
                          секрет для post-quantum resistance. Утечка PSK
                          ослабляет туннель (атакующий может расшифровать
                          handshake при компрометации приватного ключа).
                          Для админа это не новая экспозиция (у него есть
                          /config endpoint), но для user-портала PSK чужого
                          пира утекать не должен.

    server_privkey живёт в state.json (не в peer), но если бы оказался в peer —
    тоже был бы отфильтрован этим списком.
    """
    # Список полей, которые НИКОГДА не попадают в JSON-ответы API.
    # Приватные ключи и PSK — боевые секреты, отдаются только в .conf-файле
    # владельцу/админу через /api/awg/.../config и /api/awg/my-peer/config.
    _NEVER_IN_JSON = ("client_privkey", "preshared_key", "server_privkey")
    if not isinstance(peer, dict):
        return {}
    safe = {}
    for k, v in peer.items():
        if k in _NEVER_IN_JSON:
            continue
        safe[k] = v
    return safe


def _parse_peer_stats(dump_lines: list, peers: list) -> dict:
    """
    Парсит вывод `awg show all dump` и сопоставляет с peer'ами из state.
    Возвращает {peer_name: {rx_bytes, tx_bytes, handshake_ago, endpoint}}.
    Логика перенесена из awg_peers.awg_peer_stats (json-режим).
    """
    peer_stats = {}
    for line in dump_lines:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] == "peer":
            pubkey = parts[1]
            allowed_ips = parts[4] if len(parts) > 4 else ""
            rx_bytes = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
            tx_bytes = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0
            handshake = parts[5] if len(parts) > 5 else "0"
            for p in peers:
                if p.get("client_pubkey") == pubkey:
                    peer_stats[p.get("name")] = {
                        "rx_bytes":       rx_bytes,
                        "tx_bytes":       tx_bytes,
                        "handshake_ago":  handshake,
                        "endpoint":       parts[3] if len(parts) > 3 else "",
                    }
                    break
    return peer_stats


def _peer_status(peer: dict, now_iso: Optional[str] = None) -> str:
    """
    Возвращает "active" или "expired" на основе expires_at.
    Пустой expires_at = "active" (бессрочный).
    """
    expires = peer.get("expires_at", "")
    if not expires:
        return "active"
    try:
        now = now_iso or datetime.now(timezone.utc).isoformat()
        # expires_at хранится как ISO с timezone; простое строковое сравнение
        # работает для одинакового формата (оба UTC ISO).
        return "expired" if now > expires else "active"
    except Exception:
        return "active"


# ============================================================================
#  ХЕНДЛЕРЫ — GET
# ============================================================================

def awg_handle_get(handler, path: str, query: dict) -> bool:
    """
    Обрабатывает GET-запросы под /api/awg/*.
    Возвращает True если путь обработан (был наш), False если нет (404 в rest_api).
    Уже после вызова этой функции rest_api проверил авторизацию через
    handler._require_admin()/handler._require_user() — НЕТ, проверка тут.
    """
    # Все /api/awg/* endpoints требуют установленного AWG
    if not _is_awg_installed():
        handler._send_json({"error": "AmneziaWG standalone not installed"}, 404)
        return True

    # ── ADMIN endpoints ──────────────────────────────────────────────────────

    if path == "/api/awg/status":
        if not handler._require_admin("AWG Admin"):
            return True
        try:
            status = _awg_apply().awgs_service_status()
            state = _awg_state().awgs_state_load()
            handler._send_json({
                "service": status,
                "interface": state.get("interface", "awg0"),
                "port": state.get("port", 51820),
                "subnet": state.get("subnet", ""),
                "endpoint": state.get("endpoint_host") or state.get("endpoint", ""),
                "peers_count": len(state.get("peers", [])),
                "installed": True,
            })
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    if path == "/api/awg/peers":
        if not handler._require_admin("AWG Admin"):
            return True
        try:
            # Миграция: гарантируем что у всех пиров есть owner_email
            _awg_state().awgs_state_ensure_peer_owner_field()
            peers = _awg_state().awgs_state_peers_get()
            # Дополняем статистикой (если AWG-сервис активен)
            stats = {}
            try:
                dump = _awg_apply().awgs_show_dump()
                stats = _parse_peer_stats(dump, peers)
            except Exception:
                pass
            safe_peers = []
            for p in peers:
                sp = _safe_peer_for_json(p)
                st = stats.get(p.get("name"), {})
                sp["rx_bytes"] = st.get("rx_bytes", 0)
                sp["tx_bytes"] = st.get("tx_bytes", 0)
                sp["handshake_ago"] = st.get("handshake_ago", "0")
                sp["endpoint_connected"] = st.get("endpoint", "")
                sp["status"] = _peer_status(p)
                safe_peers.append(sp)
            handler._send_json({"peers": safe_peers, "count": len(safe_peers)})
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    if path == "/api/awg/stats":
        if not handler._require_admin("AWG Admin"):
            return True
        try:
            dump = _awg_apply().awgs_show_dump()
            peers = _awg_state().awgs_state_peers_get()
            stats = _parse_peer_stats(dump, peers)
            # ВАЖНО: НЕ отдаём raw_dump в JSON-ответе.
            # Формат `awg show all dump`:
            #   interface-строка: interface\t<server_privkey>\tport\t...
            #   peer-строка:      peer\t<pubkey>\t<psk>\tendpoint\t...
            # raw_dump содержал бы приватный ключ сервера (поле 1 interface)
            # и PSK каждого пира (поле 2 peer) — прямая утечка боевых секретов
            # через JSON API, нарушающая инвариант модуля ("приватные ключи
            # никогда не попадают в JSON-ответы"). Фронтенду raw_dump не нужен
            # — там уже есть распарсенные "peers" со статистикой. Для отладки
            # админ может запустить `awg show all dump` в терминале.
            handler._send_json({
                "peers": [
                    {"name": name, **st} for name, st in stats.items()
                ],
            })
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    # GET /api/awg/peers/{name}/config — .conf файл (админ видит все)
    m = re.match(r"^/api/awg/peers/([^/]+)/config$", path)
    if m:
        if not handler._require_admin("AWG Admin"):
            return True
        name = m.group(1)
        if not _validate_peer_name(name):
            handler._send_json({"error": "Invalid peer name"}, 400)
            return True
        peer = _awg_state().awgs_state_peer_find(name)
        if not peer:
            handler._send_json({"error": "peer not found"}, 404)
            return True
        try:
            state = _awg_state().awgs_state_load()
            conf = _awg_qr().awgs_qr_build_client_conf(peer, state)
            handler.send_response(200)
            handler.send_header("Content-Type", "text/plain; charset=utf-8")
            handler.send_header("Content-Disposition",
                                f'attachment; filename="{name}.conf"')
            body = conf.encode("utf-8")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    # GET /api/awg/peers/{name}/qr — PNG QR-код (админ видит все)
    m = re.match(r"^/api/awg/peers/([^/]+)/qr$", path)
    if m:
        if not handler._require_admin("AWG Admin"):
            return True
        name = m.group(1)
        if not _validate_peer_name(name):
            handler._send_json({"error": "Invalid peer name"}, 400)
            return True
        peer = _awg_state().awgs_state_peer_find(name)
        if not peer:
            handler._send_json({"error": "peer not found"}, 404)
            return True
        try:
            from .awg_constants import AWGS_KEYS_DIR
            png_path = AWGS_KEYS_DIR / f"{name}_qr.png"
            # Перегенерируем на случай если .conf изменился.
            # show_terminal=False — КРИТИЧНО: API-контекст работает под
            # systemd, stdout уходит в journal. awgs_qr_show_terminal()
            # печатает ANSI QR с vpn:// URI (приватный ключ + PSK) в stdout.
            # Без show_terminal=False приватный ключ утекал бы в journal
            # на каждый GET-запрос QR.
            _awg_qr().awgs_qr_export_peer(peer, show_terminal=False)
            if not png_path.exists():
                handler._send_json({"error": "QR PNG not generated"}, 500)
                return True
            body = png_path.read_bytes()
            handler.send_response(200)
            handler.send_header("Content-Type", "image/png")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    # ── USER endpoints ───────────────────────────────────────────────────────

    if path == "/api/awg/my-peer":
        user = handler._require_user()
        if user is None:
            return True
        email = user.get("email", "")
        peer = _awg_state().awgs_state_find_peer_by_owner(email)
        if not peer:
            handler._send_json({"peer": None}, 200)
            return True
        safe = _safe_peer_for_json(peer)
        safe["status"] = _peer_status(peer)
        # Дополняем трафиком
        try:
            dump = _awg_apply().awgs_show_dump()
            peers = _awg_state().awgs_state_peers_get()
            stats = _parse_peer_stats(dump, peers)
            st = stats.get(peer.get("name"), {})
            safe["rx_bytes"] = st.get("rx_bytes", 0)
            safe["tx_bytes"] = st.get("tx_bytes", 0)
            safe["handshake_ago"] = st.get("handshake_ago", "0")
        except Exception:
            safe["rx_bytes"] = 0
            safe["tx_bytes"] = 0
            safe["handshake_ago"] = "0"
        handler._send_json({"peer": safe})
        return True

    # GET /api/awg/my-peer/config — .conf собственного пира
    if path == "/api/awg/my-peer/config":
        user = handler._require_user()
        if user is None:
            return True
        email = user.get("email", "")
        peer = _awg_state().awgs_state_find_peer_by_owner(email)
        if not peer:
            handler._send_json({"error": "peer not found"}, 404)
            return True
        try:
            state = _awg_state().awgs_state_load()
            conf = _awg_qr().awgs_qr_build_client_conf(peer, state)
            name = peer.get("name", "client")
            handler.send_response(200)
            handler.send_header("Content-Type", "text/plain; charset=utf-8")
            handler.send_header("Content-Disposition",
                                f'attachment; filename="{name}.conf"')
            body = conf.encode("utf-8")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    # GET /api/awg/my-peer/qr — PNG собственного пира
    if path == "/api/awg/my-peer/qr":
        user = handler._require_user()
        if user is None:
            return True
        email = user.get("email", "")
        peer = _awg_state().awgs_state_find_peer_by_owner(email)
        if not peer:
            handler._send_json({"error": "peer not found"}, 404)
            return True
        try:
            from .awg_constants import AWGS_KEYS_DIR
            name = peer.get("name", "client")
            # Перегенерируем QR на случай если .conf изменился.
            # show_terminal=False — КРИТИЧНО для API-контекста (см. комментарий
            # в /api/awg/peers/{name}/qr выше): без этого приватный ключ
            # утекает в systemd journal на каждый просмотр QR юзером.
            _awg_qr().awgs_qr_export_peer(peer, show_terminal=False)
            png_path = AWGS_KEYS_DIR / f"{name}_qr.png"
            if not png_path.exists():
                handler._send_json({"error": "QR PNG not generated"}, 500)
                return True
            body = png_path.read_bytes()
            handler.send_response(200)
            handler.send_header("Content-Type", "image/png")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    # Не наш путь
    return False


# ============================================================================
#  ХЕНДЛЕРЫ — POST
# ============================================================================

def awg_handle_post(handler, path: str, body: dict) -> bool:
    """
    Обрабатывает POST-запросы под /api/awg/*.
    body — уже распарсенный JSON (dict, возможно пустой).
    Возвращает True если путь обработан, False если нет.
    """
    if not _is_awg_installed():
        handler._send_json({"error": "AmneziaWG standalone not installed"}, 404)
        return True

    # POST /api/awg/peers — создать пира
    if path == "/api/awg/peers":
        if not handler._require_admin("AWG Admin"):
            return True
        name = (body.get("name", "") or "").strip()
        expires = (body.get("expires", "") or "").strip()
        psk = bool(body.get("psk", False))
        owner_email = (body.get("owner_email", "") or "").strip()
        if not _validate_peer_name(name):
            handler._send_json({"error": "Invalid peer name (1-32 chars, [a-zA-Z0-9_-], no leading digit)"}, 400)
            return True
        try:
            ok = _awg_peers().awg_peer_add(
                name=name,
                expires=expires,
                psk=psk,
                apply=True,
                save_state=True,
                show_qr=False,  # не показываем QR в терминал — это API
                owner_email=owner_email,
            )
            if ok:
                peer = _awg_state().awgs_state_peer_find(name)
                safe = _safe_peer_for_json(peer) if peer else {}
                handler._send_json({"status": "created", "peer": safe}, 201)
            else:
                handler._send_json({"error": "Failed to create peer (check logs)"}, 500)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    # POST /api/awg/peers/{name}/regen — перегенерировать ключи пира
    m = re.match(r"^/api/awg/peers/([^/]+)/regen$", path)
    if m:
        # Этот endpoint доступен и админу (для любого пира), и юзеру
        # (только для собственного). Логика:
        #   1. Сначала пробуем admin auth — если ок, регеним любого пира.
        #   2. Если не админ — пробуем user auth и проверяем ownership.
        name = m.group(1)
        if not _validate_peer_name(name):
            handler._send_json({"error": "Invalid peer name"}, 400)
            return True
        # Пробуем admin
        if handler._check_admin_auth():
            try:
                ok = _awg_peers().awg_peer_regen(name)
                if ok:
                    peer = _awg_state().awgs_state_peer_find(name)
                    safe = _safe_peer_for_json(peer) if peer else {}
                    handler._send_json({"status": "regenerated", "peer": safe})
                else:
                    handler._send_json({"error": "peer not found or regen failed"}, 404)
            except Exception as e:
                handler._send_json({"error": str(e)}, 500)
            return True
        # Не админ — пробуем user (с rate-limit / 401 как обычно)
        user = handler._require_user()
        if user is None:
            return True
        email = user.get("email", "")
        peer = _awg_state().awgs_state_peer_find(name)
        if not peer:
            # Не говорим что пира нет — 404 как "не ваш"
            handler._send_json({"error": "peer not found"}, 404)
            return True
        if peer.get("owner_email", "") != email:
            # Чужой пир — 403 (не раскрываем существование)
            handler._send_json({"error": "peer not found"}, 404)
            return True
        try:
            ok = _awg_peers().awg_peer_regen(name)
            if ok:
                updated = _awg_state().awgs_state_peer_find(name)
                safe = _safe_peer_for_json(updated) if updated else {}
                handler._send_json({"status": "regenerated", "peer": safe})
            else:
                handler._send_json({"error": "regen failed"}, 500)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    # POST /api/awg/my-peer/regen — regen собственного пира (юзер)
    if path == "/api/awg/my-peer/regen":
        user = handler._require_user()
        if user is None:
            return True
        email = user.get("email", "")
        peer = _awg_state().awgs_state_find_peer_by_owner(email)
        if not peer:
            handler._send_json({"error": "peer not found"}, 404)
            return True
        try:
            ok = _awg_peers().awg_peer_regen(peer.get("name", ""))
            if ok:
                updated = _awg_state().awgs_state_find_peer_by_owner(email)
                safe = _safe_peer_for_json(updated) if updated else {}
                handler._send_json({"status": "regenerated", "peer": safe})
            else:
                handler._send_json({"error": "regen failed"}, 500)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    return False


# ============================================================================
#  ХЕНДЛЕРЫ — DELETE
# ============================================================================

def awg_handle_delete(handler, path: str) -> bool:
    """Обрабатывает DELETE-запросы под /api/awg/*."""
    if not _is_awg_installed():
        handler._send_json({"error": "AmneziaWG standalone not installed"}, 404)
        return True

    # DELETE /api/awg/peers/{name}
    m = re.match(r"^/api/awg/peers/([^/]+)$", path)
    if m:
        if not handler._require_admin("AWG Admin"):
            return True
        name = m.group(1)
        if not _validate_peer_name(name):
            handler._send_json({"error": "Invalid peer name"}, 400)
            return True
        peer = _awg_state().awgs_state_peer_find(name)
        if not peer:
            handler._send_json({"error": "peer not found"}, 404)
            return True
        try:
            ok = _awg_peers().awg_peer_remove(name)
            if ok:
                handler._send_json({"status": "deleted", "name": name})
            else:
                handler._send_json({"error": "delete failed"}, 500)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    return False


# ============================================================================
#  ХЕНДЛЕРЫ — PATCH
# ============================================================================

def awg_handle_patch(handler, path: str, body: dict) -> bool:
    """
    Обрабатывает PATCH-запросы под /api/awg/*.
    Используется для изменения параметров пира (dns1/dns2/expires_at/owner_email).
    """
    if not _is_awg_installed():
        handler._send_json({"error": "AmneziaWG standalone not installed"}, 404)
        return True

    # PATCH /api/awg/peers/{name} — изменить параметр пира
    m = re.match(r"^/api/awg/peers/([^/]+)$", path)
    if m:
        if not handler._require_admin("AWG Admin"):
            return True
        name = m.group(1)
        if not _validate_peer_name(name):
            handler._send_json({"error": "Invalid peer name"}, 400)
            return True
        param = (body.get("param", "") or "").strip()
        value = body.get("value", "")
        # value может быть пустой строкой (снять expires_at / owner_email)
        if not isinstance(value, str):
            value = str(value) if value is not None else ""
        if param not in ("dns1", "dns2", "expires_at", "owner_email"):
            handler._send_json({
                "error": "Unsupported param. Allowed: dns1, dns2, expires_at, owner_email"
            }, 400)
            return True
        peer = _awg_state().awgs_state_peer_find(name)
        if not peer:
            handler._send_json({"error": "peer not found"}, 404)
            return True
        try:
            ok = _awg_peers().awg_peer_modify(name, param, value)
            if ok:
                updated = _awg_state().awgs_state_peer_find(name)
                safe = _safe_peer_for_json(updated) if updated else {}
                handler._send_json({"status": "modified", "peer": safe})
            else:
                handler._send_json({"error": "modify failed (check param/value)"}, 400)
        except Exception as e:
            handler._send_json({"error": str(e)}, 500)
        return True

    return False
