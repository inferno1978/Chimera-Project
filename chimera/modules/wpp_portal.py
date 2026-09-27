"""
chimera/modules/wpp_portal.py
───────────────────────────────────────────────────────────────────────────────
User Portal — per-user cookie-based auth, all /portal/ and /api/portal/ routes.

Ported from rest_api.py (vless-web.service, deleted) into WPP Web Panel.
Uses HMAC-signed session cookies (same approach as WPP's admin session)
but with a separate cookie name (psid) and portal-specific HMAC prefix.

Routes are delegated from wpp_panel_web.py's do_GET / do_POST.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import time
from http import cookies
from urllib.parse import parse_qs, urlparse

# ── Helpers imported from rest_api (single source of truth) ─────────────────
from chimera.modules.rest_api import (
    _generate_vless_links,
    _get_user_traffic,
    _get_ttl_info,
    _get_health,
    _generate_clash_config,
    _generate_singbox_config,
    _generate_hiddify_config,
    _generate_vless_link_plain,
    _get_users,
    _save_users,
)

PORTAL_COOKIE = "psid"
PORTAL_TTL = 86400  # 24 hours

# ============================================================================
#  TRAFFIC: enhanced statistics (uplink/downlink split + daily history)
#  Reads xray Stats API directly for upload/download, traffic_history.json
#  for per-day breakdown, and traffic_limits.json for the user limit.
# ============================================================================

_TRAFFIC_HISTORY_FILE = "/var/lib/xray-installer/traffic_history.json"

_VALUE_RE = r'"value"\s*:\s*"?(\d+)"?'


def _query_user_traffic_split(email):
    """Return (uplink_bytes, downlink_bytes) via xray Stats API.

    Queries uplink and downlink counters separately so the portal can show
    a split of sent vs received traffic. Returns (0, 0) on any failure.
    """
    import re
    try:
        from chimera.modules.traffic_tracking import _core_module
        core = _core_module()
        _run = core._run
        xray_bin = str(core.XRAY_BIN)
        port = core.XRAY_STATS_API_PORT
    except Exception:
        return (0, 0)
    up = 0
    down = 0
    for direction in ("uplink", "downlink"):
        try:
            r = _run([
                xray_bin, "api", "statsquery",
                "--server=127.0.0.1:%s" % port,
                "--pattern=user>>>{0}>>>traffic>>>{1}".format(email, direction),
            ], capture=True, check=False)
            for line in (r.stdout or "").splitlines():
                m = re.search(_VALUE_RE, line)
                if m:
                    val = int(m.group(1))
                    if direction == "uplink":
                        up = val
                    else:
                        down = val
        except Exception:
            pass
    return (up, down)


def _get_user_daily_traffic(email):
    """Read traffic_history.json, return per-day traffic for the user.

    Stored values are cumulative daily maxima (xray counters grow from
    process start), so this computes per-day deltas with restart-clamping:
    if the counter dropped (xray restart), the new value is treated as
    the usage for that day.

    Returns a list sorted by date descending (newest first), max 30 entries:
        [{"date": "2026-09-27", "bytes": 50000000}, ...]
    """
    import json
    from pathlib import Path
    hist_path = Path(_TRAFFIC_HISTORY_FILE)
    if not hist_path.exists():
        return []
    try:
        history = json.loads(hist_path.read_text())
    except Exception:
        return []
    if not isinstance(history, dict) or not history:
        return []
    key = "{0}_max".format(email)
    alt_keys = [
        "awg::{0}_max".format(email),
        "mtproto::{0}_max".format(email),
        "mieru::{0}_max".format(email),
        "naiveproxy::{0}_max".format(email),
    ]
    raw = []
    for date, data in history.items():
        if not isinstance(data, dict):
            continue
        val = data.get(key, 0) or 0
        for ak in alt_keys:
            val += data.get(ak, 0) or 0
        if val > 0:
            raw.append((date, int(val)))
    if not raw:
        return []
    raw.sort(key=lambda x: x[0])
    result = []
    prev = 0
    for date, val in raw:
        if val >= prev:
            delta = val - prev
        else:
            delta = val
        result.append({"date": date, "bytes": int(delta)})
        prev = val
    result.reverse()
    return result[:30]


def _get_xray_reset_date():
    """Return the last xray (re)start timestamp as a short string, or empty."""
    import subprocess
    try:
        r = subprocess.run(
            ["systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "xray"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        out = (r.stdout or "").strip()
        if not out or out == "0":
            return ""
        try:
            r2 = subprocess.run(
                ["date", "-d", out, "+%Y-%m-%d %H:%M"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if r2.returncode == 0 and r2.stdout.strip():
                return r2.stdout.strip()
        except Exception:
            pass
        return out
    except Exception:
        return ""


def _get_user_traffic_enhanced(email):
    """Enhanced traffic stats: uplink/downlink split + daily history + meta."""
    up, down = _query_user_traffic_split(email)
    total = up + down
    daily = _get_user_daily_traffic(email)
    days_active = len(daily)
    avg_per_day = total // (days_active if days_active else 1)
    limit_gb = 0
    try:
        from chimera.modules.traffic_tracking import _limits_load
        limits = _limits_load() or {}
        cfg = limits.get(email) or {}
        if isinstance(cfg, dict):
            limit_gb = float(cfg.get("limit_gb", 0) or 0)
    except Exception:
        pass
    reset_date = _get_xray_reset_date()
    return {
        "email": email,
        "total_bytes": total,
        "total_gb": round(total / 1024 ** 3, 2),
        "upload_bytes": up,
        "download_bytes": down,
        "upload_gb": round(up / 1024 ** 3, 2),
        "download_gb": round(down / 1024 ** 3, 2),
        "daily": daily,
        "days_active": days_active,
        "avg_per_day_bytes": avg_per_day,
        "limit_gb": limit_gb,
        "reset_date": reset_date,
    }




# ============================================================================
#  SESSION / AUTH
# ============================================================================

def _session_key() -> bytes:
    """Get SESSION_KEY from wpp_panel_web (shared with admin sessions)."""
    from chimera.modules import wpp_panel_web
    return wpp_panel_web.SESSION_KEY


def _sign(x: str) -> str:
    """Sign a portal session token: 'timestamp-email' + '.' + HMAC."""
    return x + "." + hmac.new(
        _session_key(), b"portal:" + x.encode(), hashlib.sha256
    ).hexdigest()


def _cookie_value(handler, value: str, max_age: int) -> str:
    secure = (
        "; Secure"
        if handler.headers.get("X-Forwarded-Proto", "").lower() == "https"
        else ""
    )
    return (
        f"{PORTAL_COOKIE}={value}; Path=/; Max-Age={max_age}; "
        f"HttpOnly{secure}; SameSite=Lax"
    )


def _get_user(handler) -> dict | None:
    """Return user dict if portal session cookie is valid, else None."""
    c = cookies.SimpleCookie(handler.headers.get("Cookie", ""))
    v = c.get(PORTAL_COOKIE)
    if not v:
        return None
    try:
        x, _ = v.value.rsplit(".", 1)
        issued = int(x.split("-", 1)[0])
        if not (0 <= time.time() - issued < PORTAL_TTL):
            return None
        if not secrets.compare_digest(_sign(x), v.value):
            return None
        email = x.split("-", 1)[1]
        for u in _get_users():
            if u.get("email") == email:
                return u
    except Exception:
        pass
    return None


def _require_user(handler) -> dict | None:
    """Return user dict or send 401 JSON / redirect to /portal/."""
    user = _get_user(handler)
    if user is not None:
        return user
    path = urlparse(handler.path).path
    if path.startswith("/api/"):
        handler.send_json({"error": "Unauthorized"}, 401)
    else:
        _redirect(handler, "/portal/")
    return None


def _redirect(handler, location: str) -> None:
    handler.send_response(303)
    handler.send_header("Location", location)
    handler.end_headers()


def _send_json(handler, data: dict, status: int = 200) -> None:
    handler.send_json(data, status)


def _send_raw(handler, body: str, content_type: str, filename: str) -> None:
    raw = body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header(
        "Content-Disposition", f'attachment; filename="{filename}"'
    )
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _client_ip(handler) -> str:
    """Return real client IP (trust X-Forwarded-For only from loopback)."""
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
    """Dispatch all /portal/ and /api/portal/ GET routes."""

    # ── HTML pages ──────────────────────────────────────────────────────────

    if path == "/portal" or path == "/portal/":
        user = _get_user(handler)
        if user:
            _redirect(handler, "/portal/home")
        else:
            from chimera.modules.wpp_ui import portal_login_page
            handler.send_html(portal_login_page("/portal", ""))
        return

    if path == "/portal/home":
        user = _require_user(handler)
        if user is None:
            return
        from chimera.modules.wpp_ui import portal_page
        handler.send_html(portal_page(user, "/portal"))
        return

    if path == "/portal/logout":
        handler.send_response(303)
        handler.send_header(
            "Set-Cookie", _cookie_value(handler, "", 0)
        )
        handler.send_header("Location", "/portal/")
        handler.end_headers()
        return

    # /portal/{token} — auto-login by UUID
    if path.startswith("/portal/") and path != "/portal/home":
        token = path[len("/portal/"):].strip("/")
        if token and token != "home":
            for u in _get_users():
                if u.get("uuid", "") == token:
                    _start_session(handler, u)
                    return
            # Invalid token → show login with error
            from chimera.modules.wpp_ui import portal_login_page
            handler.send_html(
                portal_login_page("/portal", "Недействительная ссылка входа"),
                403,
            )
            return

    # ── JSON / download API ─────────────────────────────────────────────────

    if path == "/api/portal/links":
        user = _require_user(handler)
        if user is None:
            return
        links = _generate_vless_links(user)
        _send_json(handler, {"links": links, "count": len(links)})
        return

    if path == "/api/portal/traffic":
        user = _require_user(handler)
        if user is None:
            return
        email = user.get("email", "")
        traffic = _get_user_traffic_enhanced(email)
        ttl = _get_ttl_info(email)
        _send_json(handler, {**traffic, **ttl})
        return

    if path == "/api/portal/health":
        user = _require_user(handler)
        if user is None:
            return
        health = _get_health()
        safe = {
            "domain": health.get("domain", ""),
            "server_port": health.get("server_port", 443),
            "protocol_mode": health.get("protocol_mode", "reality"),
            "xray": health.get("xray", "unknown"),
            "ssl_days_left": health.get("ssl_days_left", -1),
            "uptime_hours": health.get("uptime_hours", 0),
            "timestamp": health.get("timestamp", ""),
        }
        _send_json(handler, safe)
        return

    if path == "/api/portal/clash":
        user = _require_user(handler)
        if user is None:
            return
        _send_raw(
            handler,
            _generate_clash_config(user),
            "text/yaml; charset=utf-8",
            "clash-meta.yaml",
        )
        return

    if path == "/api/portal/singbox":
        user = _require_user(handler)
        if user is None:
            return
        _send_raw(
            handler,
            _generate_singbox_config(user),
            "application/json; charset=utf-8",
            "sing-box.json",
        )
        return

    if path == "/api/portal/hiddify":
        user = _require_user(handler)
        if user is None:
            return
        _send_raw(
            handler,
            _generate_hiddify_config(user),
            "application/json; charset=utf-8",
            "hiddify.json",
        )
        return

    if path == "/api/portal/vless-link":
        user = _require_user(handler)
        if user is None:
            return
        _send_raw(
            handler,
            _generate_vless_link_plain(user),
            "text/plain; charset=utf-8",
            "vless-link.txt",
        )
        return

    if path == "/api/portal/sub-info":
        user = _require_user(handler)
        if user is None:
            return
        try:
            from chimera.modules.subscription import (
                get_portal_subscription_info,
            )
            _send_json(handler, get_portal_subscription_info(user))
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/sub-clash":
        user = _require_user(handler)
        if user is None:
            return
        body = ""
        try:
            from chimera.modules import subscription_multinode as _mn
            body = _mn.build_mihomo_config(user)
        except Exception:
            pass
        if not body:
            body = _generate_clash_config(user)
        if not body:
            _send_json(handler, {"error": "clash config unavailable"}, 503)
            return
        _send_raw(handler, body, "text/yaml; charset=utf-8", "chimera-mihomo.yaml")
        return

    if path == "/api/portal/sub-singbox":
        user = _require_user(handler)
        if user is None:
            return
        body = ""
        try:
            from chimera.modules import subscription_multinode as _mn
            body = _mn.build_singbox_config(user)
        except Exception:
            pass
        if not body:
            body = _generate_singbox_config(user)
        if not body:
            _send_json(handler, {"error": "singbox config unavailable"}, 503)
            return
        _send_raw(handler, body, "application/json; charset=utf-8", "chimera-singbox.json")
        return

    if path == "/api/portal/sat-info":
        user = _require_user(handler)
        if user is None:
            return
        try:
            from chimera.modules.satellite_bindings import (
                get_user_satellites_info,
            )
            _send_json(handler, {"satellites": get_user_satellites_info(user)})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/sat-suggest":
        user = _require_user(handler)
        if user is None:
            return
        try:
            from chimera.modules.satellite_bindings import suggest_for_user
            _send_json(handler, {"suggestions": suggest_for_user(user)})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/b4-info":
        user = _require_user(handler)
        if user is None:
            return
        try:
            from chimera.modules.youtube_b4 import get_portal_info
            _send_json(handler, get_portal_info())
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/ips":
        user = _require_user(handler)
        if user is None:
            return
        try:
            from chimera.modules.user_ip_whitelist import (
                get_user_ips_detailed,
                MAX_IPS_PER_USER,
            )
            email = user.get("email", "")
            ips_detailed = get_user_ips_detailed(email)
            detected = _client_ip(handler)
            if detected in ("127.0.0.1", "::1", "localhost", "?"):
                detected = ""
            _send_json(handler, {
                "ips": ips_detailed,
                "max": MAX_IPS_PER_USER,
                "detected_ip": detected,
            })
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/qr":
        user = _require_user(handler)
        if user is None:
            return
        data = query.get("data", [""])[0]
        if not data:
            _send_json(handler, {"error": "data required"}, 400)
            return
        try:
            qr_bin = subprocess.run(
                ["/usr/bin/qrencode", "-o", "-", "-t", "PNG", "-s", "6", "-m", "2", data],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True, timeout=10,
            ).stdout
            handler.send_response(200)
            handler.send_header("Content-Type", "image/png")
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("Content-Length", str(len(qr_bin)))
            handler.end_headers()
            handler.wfile.write(qr_bin)
        except Exception:
            _send_json(handler, {"error": "QR generation failed"}, 503)
        return

    # 404 fallback
    _send_json(handler, {"error": "Not found"}, 404)


# ============================================================================
#  POST ROUTES
# ============================================================================

def _start_session(handler, user: dict) -> None:
    """Create portal session cookie and redirect to /portal/home."""
    token = f"{int(time.time())}-{user.get('email', '')}"
    sid = _sign(token)
    handler.send_response(303)
    handler.send_header("Set-Cookie", _cookie_value(handler, sid, PORTAL_TTL))
    handler.send_header("Location", "/portal/home")
    handler.end_headers()


def _read_json_body(handler, maximum: int = 65536) -> dict | None:
    """Read JSON body from request. Returns dict or None on error."""
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


def handle_post(handler, path: str) -> None:
    """Dispatch all /portal/ and /api/portal/ POST routes."""

    # ── Login (form-based, no auth required) ────────────────────────────────
    if path == "/portal/login":
        try:
            form = handler.form(8192)
        except Exception:
            handler.send_html("Bad request", 400)
            return
        login = form.get("login", "").strip()
        password = form.get("password", "")
        users = _get_users()
        for u in users:
            if (
                u.get("email", "") == login
                or u.get("name", "") == login
            ):
                stored = u.get("portal_password", "")
                if stored and secrets.compare_digest(stored, password):
                    _start_session(handler, u)
                    return
                break
        # Auth failed
        from chimera.modules.wpp_ui import portal_login_page
        handler.send_html(
            portal_login_page("/portal", "Неверный логин или пароль"),
            401,
        )
        return

    # ── Change password (requires portal session) ──────────────────────────
    if path == "/portal/password":
        user = _require_user(handler)
        if user is None:
            return
        body = _read_json_body(handler)
        if body is None:
            # Try form data
            try:
                form = handler.form(8192)
                new_pass = form.get("new_password", "").strip()
            except Exception:
                _send_json(handler, {"error": "Invalid request"}, 400)
                return
        else:
            new_pass = body.get("new_password", "").strip()
        if len(new_pass) < 8:
            _send_json(handler, {"error": "Пароль минимум 8 символов"}, 400)
            return
        email = user.get("email", "")
        users = _get_users()
        for u in users:
            if u.get("email") == email:
                u["portal_password"] = new_pass
                _save_users(users)
                _send_json(handler, {"status": "changed"})
                return
        _send_json(handler, {"error": "user not found"}, 404)
        return

    # ── IP whitelist management ─────────────────────────────────────────────
    if path == "/api/portal/ips":
        user = _require_user(handler)
        if user is None:
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        ip_input = (body.get("ip") or "").strip()
        if not ip_input:
            _send_json(handler, {"error": "ip required"}, 400)
            return
        if ip_input.lower() == "auto":
            ip_input = _client_ip(handler)
            if ip_input in ("127.0.0.1", "::1", "localhost", "?"):
                _send_json(handler, {
                    "error": "auto-detect невозможен (localhost/SSH tunnel). Укажите IP вручную.",
                }, 400)
                return
        email = user.get("email", "")
        try:
            from chimera.modules.user_ip_whitelist import add_ip_to_user
            ok, msg = add_ip_to_user(email, ip_input)
            if ok:
                _send_json(handler, {"status": "added", "message": msg})
            else:
                _send_json(handler, {"error": msg}, 400)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/ips/replace-all":
        user = _require_user(handler)
        if user is None:
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        ip_input = (body.get("ip") or "").strip()
        if not ip_input:
            _send_json(handler, {"error": "ip required"}, 400)
            return
        if ip_input.lower() == "auto":
            ip_input = _client_ip(handler)
            if ip_input in ("127.0.0.1", "::1", "localhost", "?"):
                _send_json(handler, {
                    "error": "auto-detect невозможен (localhost/SSH tunnel). Укажите IP вручную.",
                }, 400)
                return
        keep_pinned = body.get("keep_pinned", True)
        email = user.get("email", "")
        try:
            from chimera.modules.user_ip_whitelist import replace_all_ips
            ok, msg = replace_all_ips(email, ip_input, keep_pinned=keep_pinned)
            if ok:
                _send_json(handler, {"status": "replaced", "message": msg})
            else:
                _send_json(handler, {"error": msg}, 400)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/ips/pin":
        user = _require_user(handler)
        if user is None:
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        ip_input = (body.get("ip") or "").strip()
        if not ip_input:
            _send_json(handler, {"error": "ip required"}, 400)
            return
        email = user.get("email", "")
        try:
            from chimera.modules.user_ip_whitelist import pin_ip_to_user
            ok, msg = pin_ip_to_user(email, ip_input)
            if ok:
                _send_json(handler, {"status": "pinned", "message": msg})
            else:
                _send_json(handler, {"error": msg}, 400)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/ips/unpin":
        user = _require_user(handler)
        if user is None:
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        ip_input = (body.get("ip") or "").strip()
        if not ip_input:
            _send_json(handler, {"error": "ip required"}, 400)
            return
        email = user.get("email", "")
        try:
            from chimera.modules.user_ip_whitelist import unpin_ip_from_user
            ok, msg = unpin_ip_from_user(email, ip_input)
            if ok:
                _send_json(handler, {"status": "unpinned", "message": msg})
            else:
                _send_json(handler, {"error": msg}, 400)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    # ── Satellite bindings (user-side) ───────────────────────────────────────
    if path == "/api/portal/sat-bind":
        user = _require_user(handler)
        if user is None:
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        satellite = body.get("satellite", "").strip()
        login = body.get("login", "").strip()
        if not satellite or not login:
            _send_json(handler, {"error": "satellite и login обязательны"}, 400)
            return
        try:
            from chimera.modules.satellite_bindings import (
                set_binding, scan_all_satellites, SATELLITES,
            )
            scan = scan_all_satellites()
            sat_key = None
            for s in SATELLITES:
                if s == satellite.lower() or s.startswith(satellite.lower()):
                    sat_key = s
                    break
            if not sat_key:
                _send_json(handler, {"error": f"unknown satellite: {satellite}"}, 400)
                return
            available_logins = [l.get("login") for l in scan.get(sat_key, [])]
            if login not in available_logins:
                _send_json(handler, {
                    "error": f"login '{login}' не найден в {sat_key}",
                }, 400)
                return
            set_binding(
                satellite=sat_key,
                login=login,
                owner_uuid=user.get("uuid", ""),
                owner_email=user.get("email", ""),
            )
            _send_json(handler, {
                "status": "bound", "satellite": sat_key, "login": login,
            })
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    if path == "/api/portal/sat-unbind":
        user = _require_user(handler)
        if user is None:
            return
        body = _read_json_body(handler)
        if body is None:
            _send_json(handler, {"error": "Payload Too Large"}, 413)
            return
        satellite = body.get("satellite", "").strip()
        if not satellite:
            _send_json(handler, {"error": "satellite обязателен"}, 400)
            return
        try:
            from chimera.modules.satellite_bindings import remove_binding
            ok = remove_binding(
                satellite=satellite,
                owner_uuid=user.get("uuid", ""),
            )
            _send_json(handler, {"status": "unbound" if ok else "not_found"})
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

    # 404 fallback
    _send_json(handler, {"error": "Not found"}, 404)

def handle_delete(handler, path):
    """Dispatch DELETE routes for /api/portal/*."""
    if path == "/api/portal/ips":
        user = _require_user(handler)
        if user is None:
            return
        from urllib.parse import parse_qs, unquote
        parsed = urlparse(handler.path)
        qs = parse_qs(parsed.query)
        ip_to_delete = ""
        if "ip" in qs and qs["ip"]:
            ip_to_delete = unquote(qs["ip"][0]).strip()
        if not ip_to_delete:
            _send_json(handler, {"error": "ip query parameter required"}, 400)
            return
        email = user.get("email", "")
        try:
            from chimera.modules.user_ip_whitelist import remove_ip_from_user
            ok, msg = remove_ip_from_user(email, ip_to_delete)
            if ok:
                _send_json(handler, {"status": "deleted", "message": msg})
            else:
                _send_json(handler, {"error": msg}, 400)
        except Exception as e:
            _send_json(handler, {"error": str(e)}, 500)
        return

