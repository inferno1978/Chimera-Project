#!/usr/bin/env python3
"""
chimera/modules/wpp_panel.py
────────────────────────────────────────────────────────────────────────────────
WPP Web Panel — админ-панель управления VPN-подключениями (VLESS/Hysteria2/
AWG/OpenFlux/MTProto). Порт проекта POLESNIESOVETI12/web-panel-proxy v2.4.2
(MIT © POLESNIESOVETI12) в нативную архитектуру Chimera.

ЧТО ЭТО:
  Отдельный веб-сервис (по паттерну B4 / Triple Panel) с фронтендом апстрима
  (vanilla JS, без сборки) и бэкендом, реализующим API-контракт панели
  поверх ГОТОВЫХ примитивов Chimera:

    • юзер-модель    → users_manager.py + state.json
    • протоколы      → xray_install.py / hysteria2_*.py / awg_*.py / mtproto.py
    • подписка       → subscription.py + subscription_multinode.py
    • трафик         → traffic_accounting.py + traffic_history.py
    • OpenFlux       → openflux.py (уже установлен)
    • доступ         → panel_nginx_front.py (SSH-туннель / self-signed / LE)
    • обновление     → download_manager.PackageSpec + WPP_FRONT_SPEC
    • порты          → port_registry.py (конфликт-чек + регистрация)

АРХИТЕКТУРА (почему отдельный сервис, а не роуты в rest_api.py):
  • свой лайфсайкл: версия фронта ≠ версия Chimera (обновляется независимо)
  • свой порт (выбирает юзер) — 9701 по умолчанию (рядом с b4 :9700)
  • паттерн B4 + Triple Panel: TUI-пункт + systemd-юнит + nginx-front + ufw

ВЕРСИИ:
  front_version — тег апстрима WPP (v2.4.2 на момент порта). upstream_version —
  последний релиз на GitHub (кэш 5 мин).
  Бэкенд-контракт — наш код в wpp_panel_web.py; апстрим гарантирует
  стабильность API в минорных релизах (см. WPP changelog "Что нового").

Точка входа из TUI (раздел 1 → W → 9):
    from chimera.modules.wpp_panel import do_wpp_panel_menu

Запуск веб-сервера (systemd):
    python3 -c "from chimera.modules.wpp_panel_web import start_server; start_server()"

ПОЛНАЯ АВТОНОМНОСТЬ: модуль НЕ требует изменений в _core.py. Ядро
резолвится лениво через _core_module() (паттерн warp.py — top-level
импорт из _core здесь запрещён циклической инициализацией).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

# ── Прямой запуск (python3 .../wpp_panel.py) — bootstrap корня проекта ───────
if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

from chimera.modules.proto_common import proto_ask, ProtoCancelled
from chimera.modules.text_width import wlen as _wlen, plain as _plain
_Cancelled = ProtoCancelled

# ─── КОНСТАНТЫ ───────────────────────────────────────────────────────────────

STATE_DIR      = Path("/var/lib/xray-installer")
_STATE_FILE    = STATE_DIR / "wpp_panel_state.json"
_WWW_DIR       = STATE_DIR / "wpp_panel_www"      # вендореный фронт апстрима
_STAGING_DIR   = STATE_DIR / "wpp_panel_staging"  # atomic-swap staging
_BACKUP_DIR    = STATE_DIR / "wpp_panel_www.bak"   # backup предыдущего фронта
_SERVICE_FILE  = Path("/etc/systemd/system/wpp-web.service")
_SERVICE_NAME  = "wpp-web"
_DEFAULT_PORT  = 9701
_PORT_TAG      = "wpp_web"   # (mirror of SERVICE_WPP_WEB in port_registry.py)
_PROJECT_ROOT  = Path(__file__).resolve().parent.parent.parent

_NGINX_STATE_FILE = STATE_DIR / "wpp_panel_nginx.json"
_NGINX_SITE_NAME  = "chimera-wpp-nginx"
DEFAULT_NGINX_PORT = 9744

# Апстрим (MIT © POLESNIESOVETI12).
_UPSTREAM_REPO_FULL    = "POLESNIESOVETI12/web-panel-proxy"
_UPSTREAM_API_LATEST   = f"https://api.github.com/repos/{_UPSTREAM_REPO_FULL}/releases/latest"
_UPSTREAM_VERSION_URLS = (
    f"https://api.github.com/repos/{_UPSTREAM_REPO_FULL}/releases/latest",
    f"https://raw.githubusercontent.com/{_UPSTREAM_REPO_FULL}/main/README.md",
    f"https://cdn.jsdelivr.net/gh/{_UPSTREAM_REPO_FULL}@main/README.md",
)
_UPSTREAM_CACHE_TTL    = 300  # 5 минут (как triple_panel._UPSTREAM_CACHE_TTL)

# ─── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("chimera._core")


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _is_root() -> bool:
    return os.geteuid() == 0


def _run(cmd: list[str] | str, *, capture: bool = False,
         timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
    """Обёртка для subprocess.run: shell=False для list, shell=True для str."""
    if isinstance(cmd, str):
        return subprocess.run(cmd, shell=True, capture_output=capture,
                              text=True, timeout=timeout, check=check)
    return subprocess.run(cmd, capture_output=capture, text=True,
                          timeout=timeout, check=check)


def _info(msg: str) -> None:
    print(f"  {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"  \u26a0  {msg}", flush=True)


def _success(msg: str) -> None:
    print(f"  \u2714  {msg}", flush=True)


def _err(msg: str) -> None:
    print(f"  \u2716  {msg}", flush=True)


# ─── STATE WRAPPERS ─────────────────────────────────────────────────────────
def _load_state() -> dict:
    """Lazy import чтобы избежать циклического импорта."""
    from chimera.modules.wpp_state import load_state
    return load_state()


def _save_state(data: dict) -> None:
    from chimera.modules.wpp_state import save_state
    save_state(data)


# ─── SYSTEMD ────────────────────────────────────────────────────────────────

def _service_active() -> bool:
    r = _run(["systemctl", "is-active", "--quiet", _SERVICE_NAME],
             capture=True, timeout=10)
    return r.returncode == 0


def _service_state() -> str:
    r = _run(["systemctl", "is-active", _SERVICE_NAME],
             capture=True, timeout=10)
    return r.stdout.strip() or "unknown"


def _write_service_unit(web_port: int) -> None:
    """Записывает systemd-юнит /etc/systemd/system/wpp-web.service."""
    # По образцу triple_panel._write_service_unit (triple_panel.py:892-910).
    # ExecStart запускает wpp_panel_web.start_server() который читает порт
    # из state.json (НЕ из аргумента — паттерн triple_panel).
    unit = f"""[Unit]
Description=Chimera WPP Web Panel (админ-панель VPN-подключений)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "from chimera.modules.wpp_panel_web import start_server; start_server()"
WorkingDirectory={_PROJECT_ROOT}
Environment=PYTHONPATH={_PROJECT_ROOT}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
    _SERVICE_FILE.write_text(unit)
    _SERVICE_FILE.chmod(0o644)
    _run(["systemctl", "daemon-reload"], timeout=15)


def _enable_service() -> None:
    _run(["systemctl", "enable", "--now", _SERVICE_NAME], timeout=30)


def _disable_service() -> None:
    _run(["systemctl", "disable", "--now", _SERVICE_NAME], timeout=30,
         check=False)
    _run(["systemctl", "reset-failed", _SERVICE_NAME], timeout=10,
         check=False)


def _restart_service() -> bool:
    r = _run(["systemctl", "restart", _SERVICE_NAME], timeout=30)
    if r.returncode != 0:
        return False
    # Ждём активации (как triple_panel._wait_service_http)
    for _ in range(15):
        if _service_active():
            return True
        time.sleep(1)
    return False


def _wait_service_http(port: int, attempts: int = 30,
                       delay: float = 1.0) -> bool:
    """GET / на http://127.0.0.1:port/ до успеха. Возвращает True если HTTP 200."""
    for i in range(attempts):
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/",
                headers={"User-Agent": "wpp-panel-smoke"},
            )
            with urllib.request.urlopen(req, timeout=3) as r:
                if r.status in (200, 302, 303, 401):  # 401 = login page (OK)
                    return True
        except urllib.error.HTTPError as exc:
            # 401/403 = login required — это нормально для защищённой панели.
            if exc.code in (401, 403, 302, 303):
                return True
        except Exception:
            pass
        time.sleep(delay)
    return False


# ─── ПОРТ ────────────────────────────────────────────────────────────────────

def _ask_web_port(current_port: int = _DEFAULT_PORT) -> Optional[int]:
    """
    Спрашивает у пользователя порт для WPP. Проверяет через port_registry.
    Возвращает int или None (отмена).

    Паттерн: triple_panel._ask_web_port (triple_panel.py:829-872).
    """
    from chimera.modules.port_registry import (
        port_is_free, port_get_conflicts, ufw_open_port,
    )
    while True:
        try:
            raw = proto_ask(
                f"  Порт веб-панели WPP [{current_port}]: ",
                default=str(current_port),
                c=True,
            )
        except _Cancelled:
            return None
        raw = raw.strip()
        if not raw:
            port = current_port
        elif raw.isdigit():
            port = int(raw)
        else:
            _warn("Введите число (1024-65535) или Enter для значения по умолчанию.")
            continue
        if not (1024 <= port <= 65535):
            _warn("Порт должен быть в диапазоне 1024-65535.")
            continue
        # Проверяем конфликты через registry + system + UFW.
        is_free, conflicts = port_is_free(port, "tcp",
                                          exclude_service=_PORT_TAG)
        if not is_free:
            _warn(f"Порт {port}/tcp занят:")
            for c in conflicts[:5]:
                _warn(f"    • {c}")
            if len(conflicts) > 5:
                _warn(f"    ... и ещё {len(conflicts)-5}")
            _warn("Выберите другой порт.")
            continue
        return port


def _register_port(port: int) -> bool:
    """Регистрирует порт в port_registry и открывает UFW (если loopback — UFW не нужен)."""
    from chimera.modules.port_registry import port_register
    ok, msg = port_register(
        _PORT_TAG, port, "tcp",
        comment=f"WPP web panel (loopback, {port})",
        force=True,
    )
    if not ok:
        _err(f"port_register failed: {msg}")
        return False
    return True


def _unregister_port(port: int) -> None:
    """Удаляет порт из registry (silent)."""
    try:
        from chimera.modules.port_registry import port_unregister
        port_unregister(_PORT_TAG, port=port, proto="tcp")
    except Exception:
        pass


# ─── ПАРОЛЬ АДМИНИСТРАТОРА ──────────────────────────────────────────────────

def _gen_admin_password() -> str:
    """16 байт случайных -> URL-safe base64 (как triple_panel._gen_admin_password)."""
    import base64
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


def _hash_password(password: str) -> tuple[str, str]:
    """
    Хэширует пароль SHA-256 с 16-байтным salt. Возвращает (salt_hex, hash_hex).
    """
    import hashlib
    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()
    h = hashlib.sha256()
    h.update(salt + password.encode("utf-8"))
    return salt_hex, h.hexdigest()


def _check_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    import hashlib
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    h = hashlib.sha256()
    h.update(salt + password.encode("utf-8"))
    actual = h.hexdigest()
    import hmac
    return hmac.compare_digest(actual, expected_hash_hex)


def _set_admin_password(state: dict, password: str) -> None:
    """Устанавливает новый пароль администратора в state dict (in-place)."""
    salt, hash_hex = _hash_password(password)
    state["admin_pass_salt"] = salt
    state["admin_pass_sha256"] = hash_hex


def _write_wpp_data_file(admin_user: str, password: str) -> None:
    """
    Создаёт/обновляет wpp_panel_data.json — WPP panel data file с admin hash.
    Использует WPP's scrypt hash_password() из wpp_panel_web.py.
    """
    try:
        from chimera.modules.wpp_panel_web import hash_password
        wpp_hash = hash_password(password)
        wpp_data = {"admin": {"user": admin_user, "hash": wpp_hash}, "users": []}
        wpp_data_file = Path("/var/lib/xray-installer/wpp_panel_data.json")
        wpp_data_file.parent.mkdir(parents=True, exist_ok=True)
        wpp_data_file.write_text(json.dumps(wpp_data, indent=2, ensure_ascii=False))
        wpp_data_file.chmod(0o600)
    except Exception as exc:
        import sys as _sys
        print(f"[WPP-PANEL] _write_wpp_data_file failed: {type(exc).__name__}: {exc}",
              file=_sys.stderr, flush=True)


def _delete_wpp_data_file() -> None:
    """Удаляет wpp_panel_data.json + wpp_panel_session.key при uninstall."""
    for f in [Path("/var/lib/xray-installer/wpp_panel_data.json"),
              Path("/var/lib/xray-installer/wpp_panel_session.key")]:
        try:
            if f.exists():
                f.unlink()
        except Exception:
            pass


# ─── АПСТРИМ ВЕРСИЯ ─────────────────────────────────────────────────────────

def _version_key(v: str) -> tuple[int, ...]:
    """
    Конвертирует строку версии "v2.4.2" в tuple (2, 4, 2) для сравнения.
    Non-numeric → 0. По образцу triple_panel._version_key.
    """
    return tuple(int(x) if x.isdigit() else 0 for x in re.findall(r"\d+", v or ""))


def _detect_upstream_version(force: bool = False) -> tuple[Optional[str], bool]:
    """
    Запрашивает последнюю версию WPP с GitHub API. Кэш 5 мин в state.json.

    Возвращает (version_str, ok). version_str может быть None при ошибке.
    """
    state = _load_state()
    cache = state.get("upstream_cache", {})
    if not force:
        checked_at = cache.get("checked_at")
        if checked_at and cache.get("version"):
            try:
                import datetime as _dt
                ts = _dt.datetime.fromisoformat(checked_at)
                age = (_dt.datetime.now(_dt.timezone.utc) - ts).total_seconds()
                if age < _UPSTREAM_CACHE_TTL:
                    return cache["version"], bool(cache.get("ok"))
            except Exception:
                pass

    # Запрос к GitHub API.
    version: Optional[str] = None
    ok = False
    try:
        req = urllib.request.Request(
            _UPSTREAM_API_LATEST,
            headers={
                "User-Agent": "Chimera-Project/WPP-panel",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
        tag = data.get("tag_name") or ""
        # Нормализуем: убираем ведущее 'v' для чистого сравнения.
        version = tag.lstrip("v") if tag else None
        if version:
            ok = True
    except Exception as exc:
        # Fallback: парсим README ("WEB PANEL PROXY X.Y.Z" в h1).
        try:
            req = urllib.request.Request(
                f"https://raw.githubusercontent.com/{_UPSTREAM_REPO_FULL}/main/README.md",
                headers={"User-Agent": "Chimera-Project/WPP-panel"},
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                text = r.read().decode("utf-8", errors="replace")
            m = re.search(r"WEB PANEL PROXY\s+(\d+\.\d+\.\d+)", text)
            if m:
                version = m.group(1)
                ok = True
        except Exception:
            pass
        if not version:
            _warn(f"upstream version check failed: {type(exc).__name__}: {exc}")

    # Обновляем кэш.
    from chimera.modules.wpp_state import update_upstream_cache
    update_upstream_cache(version, ok)
    return version, ok


def _update_availability() -> tuple[str, str, str]:
    """
    Возвращает (installed_version, upstream_version, status).
    status: "uptodate" | "available" | "unknown"
    """
    state = _load_state()
    installed = state.get("front_version", "")
    upstream, ok = _detect_upstream_version(force=False)
    if not installed or not upstream:
        return installed, upstream or "", "unknown"
    if _version_key(installed) >= _version_key(upstream):
        return installed, upstream, "uptodate"
    return installed, upstream, "available"


# ─── УСТАНОВКА ───────────────────────────────────────────────────────────────

def _install() -> tuple[bool, str]:
    """
    Устанавливает WPP Web Panel:
      1. Спрашивает порт (с conflict-check через port_registry).
      2. Генерирует пароль администратора.
      3. Скачивает фронт WPP_FRONT_SPEC через download_manager.
      4. Пишет state.json.
      5. Создаёт systemd-юнит wpp-web.service.
      6. systemctl enable --now.
      7. Smoke GET / на 127.0.0.1:port — до 30 попыток.
      8. Показывает URL доступа (SSH-tunnel default).

    Возвращает (ok, msg).
    """
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.wpp_packages import WPP_FRONT_SPEC, WPP_FRONT_VERSION

    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom

    # ── 0. Проверка root ──
    if not _is_root():
        return False, "Требуются права root (запустите от root)"

    state = _load_state()
    if state.get("installed"):
        _warn("WPP Web Panel уже установлена. Используйте пункт меню для управления.")
        return False, "Уже установлена"

    # ── 1. Спрашиваем порт ──
    _box_top("🌐  WPP WEB PANEL — УСТАНОВКА")
    _box_row(f"  Порт по умолчанию: {_DEFAULT_PORT} (рядом с b4 :9700)")
    _box_row("  Будет запрошен порт — можно выбрать любой свободный 1024-65535")
    _box_bottom()

    port = _ask_web_port(_DEFAULT_PORT)
    if port is None:
        return False, "Отмена"

    # ── 2. Регистрируем порт ──
    if not _register_port(port):
        return False, "Не удалось зарегистрировать порт"

    # ── 3. Скачиваем фронт через download_manager ──
    _info(f"Скачиваю фронтенд WPP v{WPP_FRONT_VERSION} ...")
    ok = fetch_package(
        WPP_FRONT_SPEC,
        version=WPP_FRONT_VERSION,
        progress_label="WPP front",
    )
    if not ok:
        _unregister_port(port)
        return False, ("Не удалось скачать фронтенд. Положите "
                       f"web-panel-proxy-v{WPP_FRONT_VERSION}.tar.gz "
                       "в /root/ и повторите.")

    # ── 4. Переносим staging → www (atomic swap) ──
    try:
        if _WWW_DIR.exists():
            shutil.rmtree(_WWW_DIR, ignore_errors=True)
        _STAGING_DIR.rename(_WWW_DIR)
    except OSError as exc:
        _unregister_port(port)
        return False, f"Не удалось перенести фронт в {_WWW_DIR}: {exc}"

    # ── 5. Генерируем пароль администратора ──
    admin_user = "admin"
    admin_pass = _gen_admin_password()
    state.update({
        "installed":        True,
        "web_port":         port,
        "admin_user":       admin_user,
        "front_version":    WPP_FRONT_VERSION,
        "language":         "ru",
        "installed_at":     _now_iso(),
    })
    _set_admin_password(state, admin_pass)

    # ── 5b. Создаём WPP data file (wpp_panel_data.json) ──
    # Оригинальный WPP panel.py читает admin hash из этого файла (scrypt).
    # Без него login не работает (check_password возвращает False на пустом hash).
    _write_wpp_data_file(admin_user, admin_pass)

    # ── 6. Пишем state.json ──
    _save_state(state)

    # ── 7. Создаём systemd-юнит ──
    try:
        _write_service_unit(port)
    except Exception as exc:
        _unregister_port(port)
        return False, f"Не удалось создать systemd-юнит: {exc}"

    # ── 8. Включаем сервис ──
    _enable_service()

    # ── 9. Smoke GET / на 127.0.0.1:port ──
    _info("Ожидаю готовности сервиса (до 30 секунд)...")
    if not _wait_service_http(port, attempts=30, delay=1.0):
        _warn("Сервис запустился, но не отвечает на HTTP. "
              "Проверьте: systemctl status wpp-web && journalctl -u wpp-web -n 50")
    else:
        _success("Сервис активен и отвечает на HTTP")

    # ── 10. Показываем URL доступа ──
    try:
        public_ip = _detect_public_ip()
    except Exception:
        public_ip = "<server-IP>"

    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА")
    _box_row(f"  Web UI:    http://127.0.0.1:{port}  (loopback)")
    _box_row(f"  Логин:     {admin_user}")
    _box_row(f"  Пароль:    {admin_pass}  (сохраните — показан один раз!)")
    _box_row("  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄")
    _box_row("  Доступ через SSH-туннель (default):")
    _box_row(f"    ssh -L {port}:127.0.0.1:{port} root@{public_ip}")
    _box_row(f"  Затем в браузере: http://localhost:{port}")
    _box_row("  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄")
    _box_row("  Для публичного доступа (TLS) — включите Nginx Front в меню.")
    _box_bottom()

    return True, "Установлено"


def _uninstall() -> tuple[bool, str]:
    """
    Удаляет WPP Web Panel:
      1. systemctl disable --now wpp-web.
      2. Удаляет systemd-юнит.
      3. systemctl daemon-reload.
      4. Удаляет Nginx Front (если включён).
      5. Удаляет порт из registry.
      6. Удаляет www/, staging/, backup/.
      7. Пишет state installed=False.
    """
    state = _load_state()
    if not state.get("installed"):
        return False, "Не установлена"

    port = state.get("web_port", 0)

    # 1-3. systemd
    _disable_service()
    try:
        if _SERVICE_FILE.exists():
            _SERVICE_FILE.unlink()
        _run(["systemctl", "daemon-reload"], timeout=15)
    except Exception as exc:
        _warn(f"Не удалось удалить systemd-юнит: {exc}")

    # 4. Nginx Front (если включён)
    try:
        _nginx_remove()
    except Exception as exc:
        _warn(f"Не удалось удалить Nginx Front: {exc}")

    # 5. Порт
    if port:
        _unregister_port(port)

    # 6. Директории
    for d in (_WWW_DIR, _STAGING_DIR, _BACKUP_DIR):
        try:
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass

    # 6b. Удаляем WPP data files (admin hash + session key)
    _delete_wpp_data_file()

    # 7. State
    state["installed"] = False
    state["web_port"] = 0
    state["admin_pass_salt"] = ""
    state["admin_pass_sha256"] = ""
    _save_state(state)

    return True, "Удалено"


# ─── UPDATE FRONT ────────────────────────────────────────────────────────────

def _update_front() -> tuple[bool, str]:
    """
    Обновляет фронт WPP до последней версии с GitHub.

    Паттерн: triple_panel._update_front (triple_panel.py:1076-1170).
    Flow:
      1. _detect_upstream_version(force=True) → последняя версия.
      2. Сравниваем с установленной — если уже актуально, выходим.
      3. Backup _WWW_DIR → _BACKUP_DIR.
      4. fetch_package(WPP_FRONT_SPEC, version=upstream).
      5. Atomic swap _STAGING_DIR → _WWW_DIR.
      6. systemctl restart wpp-web.
      7. Smoke GET / — если fail, rollback.
      8. state['front_version'] = upstream.
    """
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.wpp_packages import WPP_FRONT_SPEC

    state = _load_state()
    if not state.get("installed"):
        return False, "Не установлена"

    port = state.get("web_port", 0)
    installed = state.get("front_version", "")

    _info("Проверяю последнюю версию WPP на GitHub...")
    upstream, ok = _detect_upstream_version(force=True)
    if not ok or not upstream:
        return False, "Не удалось получить последнюю версию с GitHub"
    _info(f"Установлено: v{installed or '—'}  Апстрим: v{upstream}")
    if installed and _version_key(installed) >= _version_key(upstream):
        _success("Уже актуально")
        return True, "Уже актуально"

    # Backup
    _info("Создаю backup текущего фронта...")
    try:
        if _BACKUP_DIR.exists():
            shutil.rmtree(_BACKUP_DIR, ignore_errors=True)
        if _WWW_DIR.exists():
            shutil.copytree(_WWW_DIR, _BACKUP_DIR)
        else:
            _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return False, f"Backup не создан: {exc}"

    # Скачиваем новый фронт
    _info(f"Скачиваю фронтенд WPP v{upstream} ...")
    if not fetch_package(WPP_FRONT_SPEC, version=upstream,
                         progress_label="WPP front"):
        return False, "Не удалось скачать фронт (mirror ladder недоступен?)"

    # Atomic swap staging → www
    try:
        if _WWW_DIR.exists():
            shutil.rmtree(_WWW_DIR, ignore_errors=True)
        _STAGING_DIR.rename(_WWW_DIR)
    except OSError as exc:
        # Rollback: восстанавливаем из backup
        _err(f"Atomic swap не удался: {exc}")
        try:
            if _WWW_DIR.exists():
                shutil.rmtree(_WWW_DIR, ignore_errors=True)
            if _BACKUP_DIR.exists():
                _BACKUP_DIR.rename(_WWW_DIR)
        except Exception:
            pass
        return False, f"Atomic swap не удался: {exc}"

    # Рестарт сервиса
    _info("Перезапускаю wpp-web...")
    if not _restart_service():
        # Rollback
        _err("Сервис не запустился — откатываю фронт к backup")
        try:
            if _WWW_DIR.exists():
                shutil.rmtree(_WWW_DIR, ignore_errors=True)
            if _BACKUP_DIR.exists():
                _BACKUP_DIR.rename(_WWW_DIR)
            _restart_service()
        except Exception:
            pass
        return False, "Сервис не запустился после обновления — откат выполнен"

    # Smoke
    _info("Проверяю HTTP...")
    if not _wait_service_http(port, attempts=30, delay=1.0):
        _err("HTTP не отвечает — откатываю фронт к backup")
        try:
            if _WWW_DIR.exists():
                shutil.rmtree(_WWW_DIR, ignore_errors=True)
            if _BACKUP_DIR.exists():
                _BACKUP_DIR.rename(_WWW_DIR)
            _restart_service()
        except Exception:
            pass
        return False, "HTTP не отвечает после обновления — откат выполнен"

    # Save state
    state["front_version"] = upstream
    _save_state(state)
    _success(f"Фронт обновлён до v{upstream}")
    # Удаляем backup
    try:
        if _BACKUP_DIR.exists():
            shutil.rmtree(_BACKUP_DIR, ignore_errors=True)
    except Exception:
        pass
    return True, f"Обновлено до v{upstream}"


# ─── СМЕНА ПОРТА ─────────────────────────────────────────────────────────────

def _change_port() -> tuple[bool, str]:
    """Меняет порт веб-панели: ask → unregister old → register new → restart."""
    state = _load_state()
    if not state.get("installed"):
        return False, "Не установлена"
    old_port = state.get("web_port", 0)
    _info(f"Текущий порт: {old_port}")

    new_port = _ask_web_port(old_port)
    if new_port is None:
        return False, "Отмена"
    if new_port == old_port:
        return False, "Порт не изменён (тот же)"

    # Unregister old
    _unregister_port(old_port)
    # Register new
    if not _register_port(new_port):
        # Возвращаем старый
        _register_port(old_port)
        return False, "Не удалось зарегистрировать новый порт"

    # Update state + restart
    state["web_port"] = new_port
    _save_state(state)
    if not _restart_service():
        return False, "Сервис не запустился после смены порта"
    _success(f"Порт изменён: {old_port} → {new_port}")
    return True, f"Порт: {new_port}"


# ─── СМЕНА ПАРОЛЯ ────────────────────────────────────────────────────────────

def _change_password() -> tuple[bool, str]:
    """Генерирует новый пароль администратора."""
    state = _load_state()
    if not state.get("installed"):
        return False, "Не установлена"
    new_pass = _gen_admin_password()
    admin_user = state.get("admin_user", "admin")
    _set_admin_password(state, new_pass)
    # Обновляем WPP data file (scrypt hash) — без этого WPP panel login
    # не примет новый пароль (читает из wpp_panel_data.json, не из state)
    _write_wpp_data_file(admin_user, new_pass)
    _save_state(state)
    # Перезапускаем сервис чтобы он перечитал wpp_panel_data.json
    _restart_service()

    # Rotate session keys (аннулируем активные сессии — паттерн panel.py:1180).
    # В wpp_panel_web.py SESSION_KEY будет читаться из state — после save
    # новые сессии будут валидироваться против нового пароля.

    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom

    port = state.get("web_port", 0)
    try:
        public_ip = _detect_public_ip()
    except Exception:
        public_ip = "<server-IP>"

    _box_top("🔒  ПАРОЛЬ ИЗМЁНЁН")
    _box_row(f"  Логин:     {state['admin_user']}")
    _box_row(f"  Пароль:    {new_pass}  (сохраните!)")
    _box_row("  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄")
    _box_row("  Все активные сессии аннулированы — перелогиньтесь.")
    _box_row(f"  SSH-tunnel: ssh -L {port}:127.0.0.1:{port} root@{public_ip}")
    _box_row(f"  URL:        http://localhost:{port}")
    _box_bottom()
    return True, "Пароль изменён"


# ─── NGINX FRONT ─────────────────────────────────────────────────────────────

def _nginx_status() -> dict:
    """Возвращает {enabled, port, domain, self_signed, url}."""
    if not _NGINX_STATE_FILE.exists():
        return {"enabled": False}
    try:
        return json.loads(_NGINX_STATE_FILE.read_text())
    except Exception:
        return {"enabled": False}


def _nginx_install() -> tuple[bool, str]:
    """Включает Nginx Front с TLS для WPP (по образцу youtube_b4._b4_nginx_install)."""
    from chimera.modules.panel_nginx_front import (
        panel_nginx_front_install, ask_tls_mode, ask_domain,
    )
    # NB: DEFAULT_NGINX_PORT определён локально (= 9744, рядом с b4 :9743).
    # panel_nginx_front.py не экспортирует дефолт — каждый модуль держит
    # свой (как triple_panel.DEFAULT_NGINX_PORT=9761, youtube_b4.DEFAULT_B4_NGINX_PORT=9743).
    state = _load_state()
    backend_port = state.get("web_port", 0)
    if not backend_port:
        return False, "Web порт не задан"

    # Спрашиваем порт для nginx front (default 9744)
    try:
        raw = proto_ask(
            f"  Порт Nginx Front (TLS) [{DEFAULT_NGINX_PORT}]: ",
            default=str(DEFAULT_NGINX_PORT), c=True,
        )
    except _Cancelled:
        return False, "Отмена"
    try:
        front_port = int(raw.strip() or DEFAULT_NGINX_PORT)
    except ValueError:
        return False, "Некорректный порт"
    if not (1024 <= front_port <= 65535):
        return False, "Порт вне диапазона 1024-65535"

    use_self_signed, domain = ask_tls_mode()
    if use_self_signed is None:
        return False, "Отмена TLS-режима"
    if not use_self_signed and not domain:
        # LE требует domain — спросим
        domain = ask_domain()
        if not domain:
            return False, "Не указан домен для Let's Encrypt"

    _info(f"Устанавливаю Nginx Front (port={front_port}, "
          f"backend={backend_port}, "
          f"TLS={'self-signed' if use_self_signed else 'LE '+domain})...")

    ok, msg = panel_nginx_front_install(
        service_tag=_PORT_TAG_NGINX_LIT,
        port=front_port,
        backend_port=backend_port,
        site_name=_NGINX_SITE_NAME,
        state_file=_NGINX_STATE_FILE,
        title="WPP Web Panel",
        use_self_signed=use_self_signed,
        domain=domain,
        websocket_origin_rewrite=False,
        backend_http_scheme="http",
        cert_name_slug="chimera-wpp",
        mcp_proxy=False,
    )
    if not ok:
        return False, msg

    # Блокируем прямой backend-порт (как B4)
    _run(["ufw", "deny", f"{backend_port}/tcp",
          "comment", "chimera-wpp-direct-block"], capture=True, timeout=10)

    _success(f"Nginx Front включён на порту {front_port}")
    return True, msg


def _nginx_remove() -> tuple[bool, str]:
    """Отключает Nginx Front (возвращает в режим SSH-tunnel)."""
    from chimera.modules.panel_nginx_front import panel_nginx_front_remove

    status = _nginx_status()
    if not status.get("enabled"):
        return True, "Nginx Front уже выключен"

    ok, msg = panel_nginx_front_remove(
        service_tag=_PORT_TAG_NGINX_LIT,
        site_name=_NGINX_SITE_NAME,
        state_file=_NGINX_STATE_FILE,
        title="WPP Web Panel",
    )

    # Открываем прямой порт обратно (для SSH-tunnel режима)
    backend_port = status.get("backend_port", 0) or _load_state().get("web_port", 0)
    if backend_port:
        _run(["ufw", "delete", "deny", f"{backend_port}/tcp"],
             capture=True, timeout=10)

    return ok, msg


# Литерал service_tag для panel_nginx_front (как SERVICE_B4_NGINX = "chimera-b4-nginx")
_PORT_TAG_NGINX_LIT = "chimera-wpp-nginx"


# ─── ACCESS MENU ─────────────────────────────────────────────────────────────

def _detect_public_ip() -> str:
    """Получает публичный IPv4 сервера через ifconfig.me (5s timeout)."""
    try:
        req = urllib.request.Request(
            "https://ifconfig.me",
            headers={"User-Agent": "curl/8.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            ip = r.read().decode("ascii", errors="replace").strip()
            # Валидация IPv4
            socket.inet_aton(ip)
            return ip
    except Exception:
        # Fallback: ip route get
        try:
            r = _run(["ip", "route", "get", "8.8.8.8"],
                     capture=True, timeout=5)
            if r.returncode == 0:
                parts = r.stdout.split()
                if "src" in parts:
                    idx = parts.index("src")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except Exception:
            pass
    return "<server-IP>"


def _access_menu() -> None:
    """Меню доступа: 1 = toggle nginx front, Q = back."""
    while True:
        core = _core_module()
        _box_top = core._box_top
        _box_row = core._box_row
        _box_bottom = core._box_bottom

        state = _load_state()
        port = state.get("web_port", 0)
        ng = _nginx_status()
        try:
            public_ip = _detect_public_ip()
        except Exception:
            public_ip = "<server-IP>"

        _box_top("🌐  ДОСТУП К WPP WEB PANEL")
        _box_row(f"  Backend:       http://127.0.0.1:{port}  (loopback)")
        _box_row(f"  Public IP:     {public_ip}")
        if ng.get("enabled"):
            _box_row(f"  Nginx Front:   ON (port {ng.get('port', '?')}, "
                     f"TLS={'self-signed' if ng.get('self_signed') else 'LE'})")
            _box_row(f"  URL:           https://{ng.get('domain') or public_ip}:{ng.get('port', '?')}")
        else:
            _box_row("  Nginx Front:   OFF (режим SSH-туннеля)")
            _box_row("  ─────────────────────────────────────────")
            _box_row("  SSH-туннель (запустите на своей машине):")
            _box_row(f"    ssh -L {port}:127.0.0.1:{port} root@{public_ip}")
            _box_row(f"  Затем в браузере: http://localhost:{port}")
        _box_row("  ─────────────────────────────────────────")
        _box_row("  1 — Переключить Nginx Front (TLS / SSH-tunnel)")
        _box_row("  Q — Назад")
        _box_bottom()

        try:
            choice = proto_ask("  Выбор: ", c=True).strip().lower()
        except _Cancelled:
            return
        if choice == "1":
            if ng.get("enabled"):
                ok, msg = _nginx_remove()
            else:
                ok, msg = _nginx_install()
            if not ok:
                _warn(msg)
        elif choice in ("q", "й", ""):
            return


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# ─── TUI MENU ────────────────────────────────────────────────────────────────

def do_wpp_panel_menu() -> None:
    """
    Главное меню WPP Web Panel. Путь в TUI: 1 (Установка) → W (Веб-панель) → 9.
    """
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom

    while True:
        state = _load_state()
        installed = state.get("installed", False)
        port = state.get("web_port", 0)
        front_v = state.get("front_version", "")
        upstream_v, _ = _detect_upstream_version(force=False)
        ng = _nginx_status()
        svc = _service_state() if installed else "—"

        # Update availability label
        if installed and front_v and upstream_v:
            if _version_key(front_v) >= _version_key(upstream_v):
                upd = "актуально"
            else:
                upd = f"доступно v{upstream_v}"
        else:
            upd = "—" if not installed else "неизвестно"

        _box_top("🌐  WPP WEB PANEL  (порт POLESNIESOVETI12)")
        _box_row(f"  Сервис:        {svc}" if installed else "  Сервис:        не установлен")
        if installed:
            _box_row(f"  Backend:       127.0.0.1:{port}")
            _box_row(f"  Фронт:         v{front_v or '?'}  Апстрим: v{upstream_v or '?'}  [{upd}]")
            _box_row(f"  Nginx Front:   {'ON' if ng.get('enabled') else 'OFF'}")
        _box_row("  ─────────────────────────────────────────")
        if installed:
            _box_row("  1 — Запуск / Остановить сервис")
            _box_row("  2 — Обновить фронт")
            _box_row("  3 — Сменить пароль администратора")
            _box_row("  4 — Доступ (SSH / публичный IP / domain)")
            _box_row("  5 — Сменить порт панели")
            _box_row("  6 — Удалить панель")
        else:
            _box_row("  1 — Установить")
        _box_row("  Q — Назад")
        _box_bottom()

        try:
            choice = proto_ask("  Выбор: ", c=True).strip().lower()
        except _Cancelled:
            return

        try:
            if not installed:
                if choice == "1":
                    ok, msg = _install()
                    if not ok:
                        _warn(msg)
                elif choice in ("q", "й", ""):
                    return
                continue

            if choice == "1":
                if _service_active():
                    _run(["systemctl", "stop", _SERVICE_NAME], timeout=15)
                    _info("Сервис остановлен")
                else:
                    _run(["systemctl", "start", _SERVICE_NAME], timeout=15)
                    if _wait_service_http(port, attempts=15, delay=1.0):
                        _success("Сервис запущен")
                    else:
                        _warn("Сервис запущен, но HTTP не отвечает (см. journalctl)")
            elif choice == "2":
                ok, msg = _update_front()
                if not ok:
                    _warn(msg)
            elif choice == "3":
                _change_password()
            elif choice == "4":
                _access_menu()
            elif choice == "5":
                _change_port()
            elif choice == "6":
                try:
                    confirm = proto_ask(
                        "  Удалить WPP Web Panel? Фронт/state/сервис будут стёрты. [y/N]: ",
                        c=True,
                    ).strip().lower()
                except _Cancelled:
                    continue
                if confirm in ("y", "yes", "д", "да"):
                    ok, msg = _uninstall()
                    if ok:
                        _success(msg)
                    else:
                        _warn(msg)
            elif choice in ("q", "й", ""):
                return
        except KeyboardInterrupt:
            return


# ─── BACKUP REGISTRY (опционально, для unified backup) ──────────────────────

def get_backup_paths() -> list[tuple[Path, str]]:
    """
    Файлы, нужные для восстановления WPP без пере-выпуска секретов.
    Возвращаем только если панель установлена. Никогда не raise'ит.
    """
    try:
        state = _load_state()
        if not state.get("installed"):
            return []
        candidates = [
            (_STATE_FILE,           "wpp/state.json"),
            (_SERVICE_FILE,         "etc/systemd/system/wpp-web.service"),
            (_NGINX_STATE_FILE,     "wpp/nginx_front.json"),
        ]
        return [(p, arc) for p, arc in candidates if p.exists()]
    except Exception:
        return []


# ─── CLI ENTRY (для прямого запуска) ──────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--smoke":
        # GET / smoke test
        state = _load_state()
        port = state.get("web_port", 0)
        if not port:
            print("WPP not installed")
            sys.exit(1)
        ok = _wait_service_http(port, attempts=3, delay=0.5)
        sys.exit(0 if ok else 1)
    elif len(sys.argv) > 1 and sys.argv[1] == "--version":
        state = _load_state()
        port = state.get("web_port", 0)
        print(f"WPP Panel: front v{state.get('front_version', '?')}, "
              f"backend port {port}, service '{_SERVICE_NAME}'")
        sys.exit(0)
    else:
        do_wpp_panel_menu()
