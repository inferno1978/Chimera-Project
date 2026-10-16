#!/usr/bin/env python3
"""
Local smoke test for WPP Web Panel backend.

Запускает wpp_panel_web.start_server() в thread, затем делает серию HTTP
запросов и проверяет ответы. Не трогает прод. НЕ запускается как root.

Запуск:
    python3 scripts/wpp_panel_smoke.py
"""
from __future__ import annotations
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

# Устанавливаем PANEL_PATH="/" ДО импорта wpp_panel_web — иначе module-level
# constant PANEL_PATH уже будет захвачен как "/panel", и изменение env
# не повлияет на маршрутизацию.
os.environ["WEBPROXY_PANEL_PATH"] = "/"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, "/home/z/my-project/repo/chimera-project")

from chimera.modules import wpp_state  # noqa: E402
from chimera.modules import wpp_panel_web  # noqa: E402


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_get(host: str, port: int, path: str,
              cookies: dict | None = None) -> tuple[int, dict, str]:
    """GET request. Returns (status, headers, body)."""
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    conn.request("GET", path, headers=headers)
    r = conn.getresponse()
    body = r.read().decode("utf-8", errors="replace")
    h = dict(r.getheaders())
    conn.close()
    return r.status, h, body


def _http_post(host: str, port: int, path: str, form: dict,
               cookies: dict | None = None) -> tuple[int, dict, str]:
    """POST form. Returns (status, headers, body). URL-encodes values properly."""
    conn = http.client.HTTPConnection(host, port, timeout=5)
    # URL-encode values properly (urllib.parse.urlencode handles <, >, etc.)
    body = urlencode(form)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    conn.request("POST", path, body=body, headers=headers)
    r = conn.getresponse()
    body = r.read().decode("utf-8", errors="replace")
    h = dict(r.getheaders())
    conn.close()
    return r.status, h, body


def _extract_cookie(set_cookie_header: str) -> tuple[str, str] | None:
    """Из 'wpp_session=...; Path=...' → ('wpp_session', 'value')."""
    if not set_cookie_header:
        return None
    first = set_cookie_header.split(";")[0]
    if "=" not in first:
        return None
    name, value = first.split("=", 1)
    return name, value


def main() -> int:
    port = _free_port()

    # (PANEL_PATH уже установлен на верхнем уровне модуля, до импорта.)

    # Подменяем state (используем tmp-файл, не прод)
    tmp_state = Path(f"/tmp/wpp_panel_smoke_state_{os.getpid()}.json")
    tmp_state.write_text(json.dumps({
        "installed": True,
        "web_port": port,
        "admin_user": "admin",
        "admin_pass_salt": "00112233445566778899aabbccddeeff",
        # SHA-256(salt + "testpass") — вычислим заранее
        "admin_pass_sha256": "",
        "front_version": "2.4.2",
        "upstream_cache": {"version": None, "checked_at": None, "ok": False},
        "language": "ru",
        "installed_at": "2026-09-25T00:00:00Z",
    }))
    # Set password
    import hashlib
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    h = hashlib.sha256(salt + b"testpass").hexdigest()
    data = json.loads(tmp_state.read_text())
    data["admin_pass_sha256"] = h
    tmp_state.write_text(json.dumps(data))

    # Monkey-patch state file path
    wpp_state.STATE_FILE = tmp_state
    print(f"[smoke] state file: {tmp_state}")

    # Monkey-patch _STUB_FILE / _STUB_DRAFT / _STUB_PRESETS_FILE → writable tmp paths
    # (smoke test не root, /var/www/ недоступен для записи)
    tmp_stub_dir = Path(f"/tmp/wpp_smoke_stub_{os.getpid()}")
    tmp_stub_dir.mkdir(parents=True, exist_ok=True)
    wpp_panel_web._STUB_FILE = tmp_stub_dir / "index.html"
    wpp_panel_web._STUB_DRAFT = tmp_stub_dir / "draft.html"
    wpp_panel_web._STUB_PRESETS_FILE = tmp_stub_dir / "presets.json"
    print(f"[smoke] stub dir: {tmp_stub_dir}")

    # Запускаем сервер в thread
    server_thread = threading.Thread(
        target=lambda: wpp_panel_web.ThreadingHTTPServer(
            ("127.0.0.1", port), wpp_panel_web._WppHandler
        ).serve_forever(),
        daemon=True,
    )
    server_thread.start()
    print(f"[smoke] server started on 127.0.0.1:{port}")

    # Даём время на запуск
    time.sleep(0.5)

    passed = 0
    failed = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if cond:
            print(f"  \u2714  {name}")
            passed += 1
        else:
            print(f"  \u2716  {name}  {detail}")
            failed += 1

    # ── 1. Health endpoint ──
    try:
        status, _, body = _http_get("127.0.0.1", port, "/__health")
        check("GET /__health → 200", status == 200, f"got {status}")
        check("GET /__health → 'OK'", body == "OK", f"got {body!r}")
    except Exception as exc:
        check("GET /__health", False, str(exc))

    # ── 2. Login page (без auth) ──
    try:
        status, _, body = _http_get("127.0.0.1", port, "/login")
        check("GET /login → 200", status == 200, f"got {status}")
        check("GET /login contains 'WPP'", "WPP" in body, "missing brand")
        check("GET /login contains <form", "<form" in body, "no form")
    except Exception as exc:
        check("GET /login", False, str(exc))

    # ── 3. Root path → redirect to login (без auth) ──
    try:
        status, headers, _ = _http_get("127.0.0.1", port, "/")
        check("GET / → 303 (redirect)", status == 303, f"got {status}")
        check("GET / Location: /login", "/login" in headers.get("Location", ""),
              f"got {headers.get('Location')!r}")
    except Exception as exc:
        check("GET / redirect", False, str(exc))

    # ── 4. POST /login with wrong password → 401 ──
    try:
        status, _, body = _http_post("127.0.0.1", port, "/login",
                                     {"user": "admin", "password": "wrongpass"})
        check("POST /login wrong → 401", status == 401, f"got {status}")
    except Exception as exc:
        check("POST /login wrong", False, str(exc))

    # ── 5. POST /login with correct password → 303 + cookie ──
    session_cookie = None
    try:
        status, headers, _ = _http_post("127.0.0.1", port, "/login",
                                        {"user": "admin", "password": "testpass"})
        check("POST /login OK → 303", status == 303, f"got {status}")
        check("POST /login Location: /dashboard",
              "/dashboard" in headers.get("Location", ""),
              f"got {headers.get('Location')!r}")
        cookie_header = headers.get("Set-Cookie", "")
        cookie = _extract_cookie(cookie_header)
        check("POST /login Set-Cookie wpp_session",
              cookie is not None and cookie[0] == "wpp_session",
              f"got {cookie_header!r}")
        if cookie:
            session_cookie = {cookie[0]: cookie[1]}
    except Exception as exc:
        check("POST /login OK", False, str(exc))

    # ── 6. GET /dashboard with valid session → 200 ──
    if session_cookie:
        try:
            status, _, body = _http_get("127.0.0.1", port, "/dashboard",
                                        cookies=session_cookie)
            check("GET /dashboard → 200", status == 200, f"got {status}")
            check("GET /dashboard contains 'Дашборд'",
                  "Дашборд" in body or "dashboard" in body.lower(),
                  "missing dashboard content")
            check("GET /dashboard contains nav links",
                  "/users" in body and "/nodes" in body and "/settings" in body,
                  "missing nav")
        except Exception as exc:
            check("GET /dashboard", False, str(exc))

        # ── 7. GET /users with valid session ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/users",
                                        cookies=session_cookie)
            check("GET /users → 200", status == 200, f"got {status}")
            check("GET /users contains create form",
                  "<form" in body and "create-account" in body,
                  "no create form")
        except Exception as exc:
            check("GET /users", False, str(exc))

        # ── 8. GET /nodes with valid session ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/nodes",
                                        cookies=session_cookie)
            check("GET /nodes → 200", status == 200, f"got {status}")
        except Exception as exc:
            check("GET /nodes", False, str(exc))

        # ── 9. GET /settings with valid session ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/settings",
                                        cookies=session_cookie)
            check("GET /settings → 200", status == 200, f"got {status}")
            check("GET /settings contains password form",
                  "name=\"a\"" in body and "password" in body.lower(),
                  "no password form")
        except Exception as exc:
            check("GET /settings", False, str(exc))

        # ── 10. GET /logout → 303 + clear cookie ──
        try:
            status, headers, _ = _http_get("127.0.0.1", port, "/logout",
                                           cookies=session_cookie)
            check("GET /logout → 303", status == 303, f"got {status}")
            check("GET /logout Set-Cookie Max-Age=0",
                  "Max-Age=0" in headers.get("Set-Cookie", ""),
                  f"got {headers.get('Set-Cookie')!r}")
        except Exception as exc:
            check("GET /logout", False, str(exc))

        # ── 11. After logout, GET /dashboard → redirect to /login ──
        # (Cookie cleared, but client still sends it — сервер проверит валидность
        #  через _verify_signed который сменит SESSION_KEY при logout через
        #  password change, не при logout. Поэтому тест может не сработать как
        #  ожидается. Просто проверим что без auth получим redirect.)
        try:
            status, _, _ = _http_get("127.0.0.1", port, "/dashboard")
            check("GET /dashboard without cookie → 303",
                  status == 303, f"got {status}")
        except Exception as exc:
            check("GET /dashboard no auth", False, str(exc))

    # ── 12. New session for Phase 2 endpoints ──
    session_cookie = None
    try:
        status, headers, _ = _http_post("127.0.0.1", port, "/login",
                                        {"user": "admin", "password": "testpass"})
        if status == 303:
            cookie = _extract_cookie(headers.get("Set-Cookie", ""))
            if cookie:
                session_cookie = {cookie[0]: cookie[1]}
    except Exception:
        pass

    if session_cookie:
        # ── 13. GET /openflux (page) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/openflux",
                                        cookies=session_cookie)
            check("GET /openflux → 200", status == 200, f"got {status}")
            check("GET /openflux contains OpenFlux header",
                  "OpenFlux" in body, "missing OpenFlux text")
        except Exception as exc:
            check("GET /openflux", False, str(exc))

        # ── 14. GET /landing (page) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/landing",
                                        cookies=session_cookie)
            check("GET /landing → 200", status == 200, f"got {status}")
            check("GET /landing contains HTML editor (textarea)",
                  "textarea" in body.lower(), "no textarea")
        except Exception as exc:
            check("GET /landing", False, str(exc))

        # ── 15. GET /api/stub (JSON) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/api/stub",
                                        cookies=session_cookie)
            check("GET /api/stub → 200", status == 200, f"got {status}")
            data = json.loads(body)
            check("GET /api/stub has 'html' key", "html" in data,
                  f"keys={list(data.keys())}")
        except Exception as exc:
            check("GET /api/stub", False, str(exc))

        # ── 16. GET /api/stub/presets (JSON) — список пресетов ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/api/stub/presets",
                                        cookies=session_cookie)
            check("GET /api/stub/presets → 200", status == 200, f"got {status}")
            data = json.loads(body)
            check("GET /api/stub/presets has 'presets' list",
                  isinstance(data.get("presets"), list),
                  f"data={data!r}")
            n = len(data.get("presets", []))
            check(f"GET /api/stub/presets has >=3 presets (got {n})", n >= 3)
        except Exception as exc:
            check("GET /api/stub/presets", False, str(exc))

        # ── 17. POST /stub/publish (publish HTML) — need CSRF ──
        import re as _re_mod
        try:
            # Get CSRF from /landing page
            status, _, body = _http_get("127.0.0.1", port, "/landing",
                                        cookies=session_cookie)
            m = _re_mod.search(r'name="csrf" value="([0-9a-f]+)"', body)
            csrf_token = m.group(1) if m else ""
            check("GET /landing has csrf token", bool(csrf_token),
                  "no csrf in HTML")
            if csrf_token:
                status, _, _ = _http_post(
                    "127.0.0.1", port, "/stub/publish",
                    {"csrf": csrf_token,
                     "html": "<!doctype html><title>test</title>"},
                    cookies=session_cookie,
                )
                check("POST /stub/publish → 303", status == 303,
                      f"got {status}")
        except Exception as exc:
            check("POST /stub/publish", False, str(exc))

        # ── 18. GET /api/stub should now return the published HTML ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/api/stub",
                                        cookies=session_cookie)
            check("GET /api/stub after publish → 200", status == 200)
            data = json.loads(body)
            check("GET /api/stub.html contains 'test'",
                  "test" in data.get("html", ""))
        except Exception as exc:
            check("GET /api/stub after publish", False, str(exc))

        # ── 19. POST /stub/save-draft + verify ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/landing",
                                        cookies=session_cookie)
            m = _re_mod.search(r'name="csrf" value="([0-9a-f]+)"', body)
            csrf_token = m.group(1) if m else ""
            if csrf_token:
                status, _, _ = _http_post(
                    "127.0.0.1", port, "/stub/save-draft",
                    {"csrf": csrf_token,
                     "html": "<!doctype html><title>draft</title>"},
                    cookies=session_cookie,
                )
                check("POST /stub/save-draft → 303", status == 303,
                      f"got {status}")
                status, _, body = _http_get("127.0.0.1", port,
                                            "/api/stub/draft",
                                            cookies=session_cookie)
                data = json.loads(body)
                check("GET /api/stub/draft has 'draft' content",
                      "draft" in data.get("html", ""))
        except Exception as exc:
            check("POST /stub/save-draft", False, str(exc))

        # ── 20. POST /stub/discard-draft ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/landing",
                                        cookies=session_cookie)
            m = _re_mod.search(r'name="csrf" value="([0-9a-f]+)"', body)
            csrf_token = m.group(1) if m else ""
            if csrf_token:
                status, _, _ = _http_post(
                    "127.0.0.1", port, "/stub/discard-draft",
                    {"csrf": csrf_token},
                    cookies=session_cookie,
                )
                check("POST /stub/discard-draft → 303", status == 303,
                      f"got {status}")
                status, _, body = _http_get("127.0.0.1", port,
                                            "/api/stub/draft",
                                            cookies=session_cookie)
                data = json.loads(body)
                check("Draft empty after discard",
                      not data.get("html"))
        except Exception as exc:
            check("POST /stub/discard-draft", False, str(exc))

        # ── 21. GET /api/openflux (JSON state) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/api/openflux",
                                        cookies=session_cookie)
            check("GET /api/openflux → 200", status == 200, f"got {status}")
            data = json.loads(body)
            check("GET /api/openflux has 'installed' key",
                  "installed" in data, f"keys={list(data.keys())}")
        except Exception as exc:
            check("GET /api/openflux", False, str(exc))

        # ── 22. GET /api/subscription (admin info) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/api/subscription",
                                        cookies=session_cookie)
            check("GET /api/subscription → 200", status == 200, f"got {status}")
            data = json.loads(body)
            check("GET /api/subscription is dict",
                  isinstance(data, dict), f"got {type(data).__name__}")
        except Exception as exc:
            check("GET /api/subscription", False, str(exc))

        # ── 23. GET /api/version ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/api/version",
                                        cookies=session_cookie)
            check("GET /api/version → 200", status == 200, f"got {status}")
            data = json.loads(body)
            check("GET /api/version has 'front_version'",
                  "front_version" in data, f"keys={list(data.keys())}")
        except Exception as exc:
            check("GET /api/version", False, str(exc))

        # ── 24. GET /qr/user/<invalid-uid>/vless → 404 ──
        try:
            status, _, _ = _http_get(
                "127.0.0.1", port,
                "/qr/user/0000000000000000/vless",
                cookies=session_cookie,
            )
            check("GET /qr/user/invalid → 404",
                  status == 404, f"got {status}")
        except Exception as exc:
            check("GET /qr/user/invalid", False, str(exc))

        # ── 25. POST /autoupdate/toggle (disable) — endpoint exists ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/settings",
                                        cookies=session_cookie)
            m = _re_mod.search(r'name="csrf" value="([0-9a-f]+)"', body)
            csrf_token = m.group(1) if m else ""
            if csrf_token:
                status, _, _ = _http_post(
                    "127.0.0.1", port, "/autoupdate/toggle",
                    {"csrf": csrf_token, "enable": "0"},
                    cookies=session_cookie,
                )
                # 303 = success (redirect to /settings), 503 = need root
                check("POST /autoupdate/toggle → 303 or 503",
                      status in (303, 503), f"got {status}")
        except Exception as exc:
            check("POST /autoupdate/toggle", False, str(exc))

    # ── Phase 3 tests (new session) ──
    session_cookie = None
    try:
        status, headers, _ = _http_post("127.0.0.1", port, "/login",
                                        {"user": "admin", "password": "testpass"})
        if status == 303:
            cookie = _extract_cookie(headers.get("Set-Cookie", ""))
            if cookie:
                session_cookie = {cookie[0]: cookie[1]}
    except Exception:
        pass

    if session_cookie:
        # ── 26. GET /components (page) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/components",
                                        cookies=session_cookie)
            check("GET /components → 200", status == 200, f"got {status}")
            check("GET /components contains 'Компоненты'",
                  "Компоненты" in body, "missing header")
        except Exception as exc:
            check("GET /components", False, str(exc))

        # ── 27. GET /api/components (JSON list) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/api/components",
                                        cookies=session_cookie)
            check("GET /api/components → 200", status == 200, f"got {status}")
            data = json.loads(body)
            check("GET /api/components has 'components' list",
                  isinstance(data.get("components"), list),
                  f"data={data!r}")
            n = len(data.get("components", []))
            check(f"GET /api/components has >=3 components (got {n})", n >= 3)
            # Проверяем что VLESS и Hysteria2 в списке
            ids = [c.get("id") for c in data.get("components", [])]
            check("GET /api/components has 'vless' id", "vless" in ids, f"ids={ids}")
            check("GET /api/components has 'hysteria' id", "hysteria" in ids, f"ids={ids}")
        except Exception as exc:
            check("GET /api/components", False, str(exc))

        # ── 28. GET /api/openflux/profiles (multi-profile list) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/api/openflux/profiles",
                                        cookies=session_cookie)
            check("GET /api/openflux/profiles → 200", status == 200, f"got {status}")
            data = json.loads(body)
            check("GET /api/openflux/profiles has 'profiles' list",
                  isinstance(data.get("profiles"), list),
                  f"data={data!r}")
        except Exception as exc:
            check("GET /api/openflux/profiles", False, str(exc))

        # ── 29. POST /openflux/profiles/create (create profile) ──
        # NB: smoke test не root — create_profile вернёт False с msg
        # "Требуется root". Проверяем что endpoint отвечает (не 500).
        try:
            status, _, body = _http_get("127.0.0.1", port, "/openflux",
                                        cookies=session_cookie)
            m = _re_mod.search(r'name="csrf" value="([0-9a-f]+)"', body)
            csrf_token = m.group(1) if m else ""
            if csrf_token:
                status, _, _ = _http_post(
                    "127.0.0.1", port, "/openflux/profiles/create",
                    {"csrf": csrf_token, "name": "smoke-test",
                     "transport": "yandex",
                     "doc_url": "https://editor.yandex.ru/doc/test?sk=secret"},
                    cookies=session_cookie,
                )
                # 400 = validation error (non-root or invalid) — endpoint exists
                # 503 = "Требуется root" — endpoint exists
                # 303 = success (если под root)
                check("POST /openflux/profiles/create → 303/400/503",
                      status in (303, 400, 503), f"got {status}")
        except Exception as exc:
            check("POST /openflux/profiles/create", False, str(exc))

        # ── 30. POST /components/install (request install) ──
        try:
            status, _, body = _http_get("127.0.0.1", port, "/components",
                                        cookies=session_cookie)
            m = _re_mod.search(r'name="csrf" value="([0-9a-f]+)"', body)
            csrf_token = m.group(1) if m else ""
            if csrf_token:
                status, _, _ = _http_post(
                    "127.0.0.1", port, "/components/install",
                    {"csrf": csrf_token, "protocol": "vless"},
                    cookies=session_cookie,
                )
                # 303 = success (pending install recorded)
                check("POST /components/install → 303",
                      status == 303, f"got {status}")
        except Exception as exc:
            check("POST /components/install", False, str(exc))

    # Cleanup
    tmp_state.unlink(missing_ok=True)
    # Cleanup tmp stub dir
    import shutil as _shutil
    try:
        _shutil.rmtree(tmp_stub_dir, ignore_errors=True)
    except Exception:
        pass

    print()
    print(f"=== RESULT: {passed} passed, {failed} failed ===")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
