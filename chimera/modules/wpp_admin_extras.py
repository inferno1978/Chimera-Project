"""
chimera/modules/wpp_admin_extras.py
───────────────────────────────────────────────────────────────────────────────
Admin gap features — routes that require WPP admin session auth.

Ported from rest_api.py (vless-web.service, deleted) into WPP Web Panel.
Uses the existing WPP admin session (cookie-based, self.auth()).

Routes:
  GET    /api/health              — detailed system health
  GET    /api/backup/list          — list backups
  GET    /api/geoip/rules         — list GeoIP rules
  POST   /api/rotate/uuid          — rotate user UUID
  POST   /api/rotate/reality       — rotate REALITY keys
  POST   /api/backup               — create backup
  POST   /api/geoip/rules         — add GeoIP rule
  DELETE /api/geoip/rules         — delete all GeoIP rules
  POST   /api/users/{email}/toggle  — ban/unban user
  POST   /api/users/{email}/rename  — rename user
  POST   /api/users/{email}/password — set portal password
  POST   /api/sat/bind             — bind satellite (admin)
  POST   /api/sat/unbind           — unbind satellite (admin)
  POST   /api/b4/install           — install b4
  POST   /api/b4/uninstall         — uninstall b4
  POST   /api/b4/enable            — enable b4
  POST   /api/b4/disable           — disable b4
  POST   /api/b4/preset            — set b4 preset
  POST   /api/b4/discovery         — run b4 discovery
  GET/POST /api/awg/*              — AWG management (delegated)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from chimera.modules.rest_api import (
    _get_users,
    _save_users,
    _get_health,
    _get_user_traffic,
    _get_ttl_info,
    _sync_users_from_config,
)


# ============================================================================
#  AUTH HELPERS
# ============================================================================

def _require_admin(handler) -> bool:
    """Check WPP admin session. If not authed, send 401 JSON."""
    if handler.auth():
        return True
    handler.send_json({"error": "Unauthorized"}, 401)
    return False


def _read_json_body(handler, maximum: int = 65536) -> dict | None:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return None
    if length < 2 or length > maximum:
        return None
    try:
        raw = handler.rfile.read(length).decode("utf-8")
        value = json.loads(raw)
        if not isinstance(value, dict):
            return None
        return value
    except Exception:
        return None


def _send_json(handler, data: dict, status: int = 200) -> None:
    handler.send_json(data, status)


def _client_ip(handler) -> str:
    try:
        direct = handler.client_address[0] if handler.client_address else "?"
    except Exception:
        return "?"
    if direct in ("127.0.0.1", "::1", "localhost"):
        xff = handler.headers.get("X-Forwarded-For", "")
        if xff:
            candidate = xff.split(",")[0].strip()
            if candidate:
                return candidate
    return direct


# ============================================================================
#  GET ROUTES
# ============================================================================

def handle_get(handler, path: str, query: dict) -> None:
    """Dispatch admin GET routes."""

    if path == "/api/health":
        if not _require_admin(handler):
            return
        _send_json(handler, _get_health())
        return

    if path == "/api/backup/list":
        if not _require_admin(handler):
            return
        backups = []
        backup_dir = Path("/var/lib/xray-installer/backups")
        if backup_dir.exists():
            for d in sorted(backup_dir.iterdir(), reverse=True):
                if d.is_dir() and d.name.startswith("config_"):
                    backups.append({"name": d.name, "path": str(d)})
        _send_json(handler, {"backups": backups, "count": len(backups)})
        return

    if path == "/api/geoip/rules":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.geoip_block import _geoip_block_get_rules
            rules = _geoip_block_get_rules()
            _send_json(handler, {"rules": rules, "count": len(rules)})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    # GET /api/users/{email}/traffic
    m = re.match(r"^/api/users/(.+)/traffic$", path)
    if m:
        if not _require_admin(handler):
            return
        email = unquote(m.group(1))
        traffic = _get_user_traffic(email)
        ttl = _get_ttl_info(email)
        _send_json(handler, {**traffic, **ttl})
        return

    # AWG management — delegate to awg_rest_api
    if path.startswith("/api/awg/"):
        try:
            from chimera.modules import awg_rest_api
            awg_rest_api.awg_handle_get(handler, path, query)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    _send_json(handler, {"error": "Not found"}, 404)


# ============================================================================
#  POST ROUTES
# ============================================================================

def handle_post(handler, path: str) -> None:
    """Dispatch admin POST routes."""

    # ── Credential rotation ──────────────────────────────────────────────────
    if path == "/api/rotate/uuid":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.credential_rotation import _uuid_rotate_now
            new_uuid = _uuid_rotate_now()
            if new_uuid:
                _send_json(handler, {"status": "rotated", "new_uuid": new_uuid})
            else:
                _send_json(handler, {"error": "rotation failed"}, 500)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/rotate/reality":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.credential_rotation import _rotate_reality_keys
            new_keys = _rotate_reality_keys()
            if new_keys:
                _send_json(handler, {"status": "rotated", **new_keys})
            else:
                _send_json(handler, {"error": "rotation failed"}, 500)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    # ── Backup ────────────────────────────────────────────────────────────────
    if path == "/api/backup":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.backup_rollback import create_backup
            create_backup()
            _send_json(handler, {"status": "backup_created"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    # ── GeoIP rules ───────────────────────────────────────────────────────────
    if path == "/api/geoip/rules":
        if not _require_admin(handler):
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        codes = body.get("codes", [])
        mode = body.get("mode", "block")
        try:
            from chimera.modules.geoip_block import (
                _geoip_set_allowlist, _geoip_add_country_block,
            )
            if mode == "allow":
                _geoip_set_allowlist(codes)
            else:
                _geoip_add_country_block(codes)
            _send_json(handler, {
                "status": "applied", "codes": codes, "mode": mode,
            })
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    # ── User management ───────────────────────────────────────────────────────
    # POST /api/users/{email}/toggle — ban/unban
    m = re.match(r"^/api/users/(.+)/toggle$", path)
    if m:
        if not _require_admin(handler):
            return
        email = unquote(m.group(1))
        users = _get_users()
        for u in users:
            if u.get("email") == email:
                u["disabled"] = not u.get("disabled", False)
                if u["disabled"]:
                    from datetime import datetime
                    u["disabled_at"] = datetime.now().isoformat()
                else:
                    u.pop("disabled_at", None)
                _save_users(users)
                try:
                    from chimera.modules import rest_api
                    core = rest_api._core_module()
                    core._users_apply_to_config(users)
                except Exception:
                    pass
                if u["disabled"]:
                    try:
                        from chimera.modules.rest_api import _sync_remove_user
                        _sync_remove_user(u.get("name", ""), user=u)
                    except Exception:
                        pass
                else:
                    try:
                        from chimera.modules.rest_api import _sync_ensure_user
                        _sync_ensure_user(u.get("name", ""), user=u)
                    except Exception:
                        pass
                new_state = "disabled" if u["disabled"] else "enabled"
                _send_json(handler, {"status": new_state, "email": email})
                return
        _send_json(handler, {"error": "user not found"}, 404)
        return

    # POST /api/users/{email}/rename
    m = re.match(r"^/api/users/(.+)/rename$", path)
    if m:
        if not _require_admin(handler):
            return
        email = unquote(m.group(1))
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        new_name = (body.get("new_name", "") or "").strip()
        if not new_name:
            _send_json(handler, {"error": "new_name required"}, 400)
            return
        if len(new_name) < 3 or len(new_name) > 32:
            _send_json(handler, {"error": "Имя должно быть 3-32 символа"}, 400)
            return
        users = _get_users()
        target = None
        for u in users:
            if u.get("email") == email:
                target = u
                break
        if target is None:
            _send_json(handler, {"error": "user not found"}, 404)
            return
        old_name = target.get("name", "") or target.get("email", "").split("@")[0]
        old_user_dict = dict(target)
        target["name"] = new_name
        _save_users(users)
        try:
            from chimera.modules.rest_api import _sync_rename_user
            _sync_rename_user(
                old_name, new_name,
                old_user=old_user_dict, new_user=dict(target),
            )
        except Exception:
            pass
        _send_json(handler, {
            "status": "renamed",
            "email": email,
            "old_name": old_name,
            "new_name": new_name,
        })
        return

    # POST /api/users/{email}/password — set portal password
    m = re.match(r"^/api/users/(.+)/password$", path)
    if m:
        if not _require_admin(handler):
            return
        email = unquote(m.group(1))
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        new_pass = body.get("new_password", "").strip()
        if len(new_pass) < 8:
            _send_json(handler, {"error": "Пароль минимум 8 символов"}, 400)
            return
        users = _get_users()
        for u in users:
            if u.get("email") == email:
                u["portal_password"] = new_pass
                _save_users(users)
                _send_json(handler, {"status": "changed", "email": email})
                return
        _send_json(handler, {"error": "user not found"}, 404)
        return

    # ── Satellite bindings (admin CRUD) ───────────────────────────────────────
    if path == "/api/sat/bind":
        if not _require_admin(handler):
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        try:
            from chimera.modules.satellite_bindings import set_binding
            ok = set_binding(
                satellite=body.get("satellite", ""),
                login=body.get("login", ""),
                owner_uuid=body.get("owner_uuid", ""),
                owner_email=body.get("owner_email", ""),
            )
            if ok:
                _send_json(handler, {"status": "bound"})
            else:
                _send_json(handler, {"error": "invalid arguments"}, 400)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/sat/unbind":
        if not _require_admin(handler):
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        try:
            from chimera.modules.satellite_bindings import remove_binding
            ok = remove_binding(
                satellite=body.get("satellite", ""),
                owner_uuid=body.get("owner_uuid", ""),
            )
            _send_json(handler, {"status": "unbound" if ok else "not_found"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    # ── b4 management (admin) ─────────────────────────────────────────────────
    if path == "/api/b4/install":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.youtube_b4 import install_b4
            ok = install_b4()
            _send_json(handler, {"status": "installed" if ok else "failed"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/b4/uninstall":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.youtube_b4 import uninstall_b4
            uninstall_b4()
            _send_json(handler, {"status": "uninstalled"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/b4/enable":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.youtube_b4 import enable
            ok = enable()
            _send_json(handler, {"status": "enabled" if ok else "failed"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/b4/disable":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.youtube_b4 import disable
            disable()
            _send_json(handler, {"status": "disabled"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/b4/preset":
        if not _require_admin(handler):
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        try:
            from chimera.modules.youtube_b4 import switch_preset
            ok = switch_preset(body.get("preset", ""))
            _send_json(handler, {"status": "switched" if ok else "failed"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/b4/discovery":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.youtube_b4 import run_discovery
            result = run_discovery(timeout_sec=60)
            _send_json(handler, result)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    # ── AWG management — delegate to awg_rest_api ─────────────────────────────
    if path.startswith("/api/awg/"):
        try:
            from chimera.modules import awg_rest_api
            body = _read_json_body(handler)
            if body is None:
                _send_json(handler, {"error": "Invalid JSON body"}, 400)
                return
            awg_rest_api.awg_handle_post(handler, path, body)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    _send_json(handler, {"error": "Not found"}, 404)


# ============================================================================
#  DELETE ROUTES
# ============================================================================

def handle_delete(handler, path: str) -> None:
    """Dispatch admin DELETE routes."""

    if path == "/api/geoip/rules":
        if not _require_admin(handler):
            return
        try:
            from chimera.modules.geoip_block import _geoip_remove_all
            _geoip_remove_all()
            _send_json(handler, {"status": "cleared"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    _send_json(handler, {"error": "Not found"}, 404)
