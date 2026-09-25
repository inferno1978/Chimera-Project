#!/usr/bin/env python3
"""
chimera/modules/openflux_profiles.py
────────────────────────────────────────────────────────────────────────────────
Multi-profile OpenFlux management — не трогает существующий single-profile
chimera/modules/openflux.py. Каждый профиль имеет собственный systemd unit
через template: openflux@<name>.service.

АРХИТЕКТУРА (Option B — обёртка, безопасная для существующего кода):
  • State file: /var/lib/xray-installer/openflux_profiles.json
    {
      "profiles": {
        "default":  {"transport":"yandex","doc_url":"...","enabled":true,"created_at":...},
        "ios-prof": {"transport":"vyandex","doc_url":"...","enabled":false,"created_at":...},
      }
    }
  • Per-profile files (root-owned, 0600):
    /etc/openflux/<name>/openflux.env     — env vars для systemd unit
    /etc/openflux/<name>/transport.key   — base64(32 random bytes) AES-256-GCM key
    /etc/openflux/<name>/client-bundle.txt — полная клиентская конфигурация
  • Per-profile systemd unit (через template):
    systemctl enable --now openflux@<name>
    systemctl disable --now openflux@<name>
  • Template unit: /etc/systemd/system/openflux@.service
    EnvironmentFile=/etc/openflux/%i/openflux.env

Backward compat:
  • Если существующий single-profile openflux.service активен — добавляем
    его в profiles как "default" (no-op migration).
  • Если /var/lib/xray-installer/openflux.json существует, но profiles.json
    нет — мигрируем автоматически.

Public API:
  profile_states()             — list of {name, transport, enabled, doc_url_masked, ...}
  create_profile(name, transport, doc_url)  → (ok, msg)
  set_enabled(name, enable)    → (ok, msg)
  rotate_key(name)             → (ok, msg)
  delete_profile(name)         → (ok, msg)
  get_profile_detail(name)     → dict (для UI, без secret)
  list_profiles()              — alias для profile_states()
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# Bootstrap корня проекта
if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

from chimera.modules.proto_common import proto_load_state, proto_save_state  # noqa: E402

# ─── КОНСТАНТЫ ───────────────────────────────────────────────────────────────

STATE_FILE      = Path("/var/lib/xray-installer/openflux_profiles.json")
OPENFLUX_DIR    = Path("/etc/openflux")                 # /etc/openflux/<name>/
TEMPLATE_UNIT   = Path("/etc/systemd/system/openflux@.service")
TEMPLATE_NAME   = "openflux@.service"                  # for systemctl
SERVICE_PREFIX  = "openflux@"                            # + name

DEFAULT_STATE: dict = {
    "profiles": {},   # name → {transport, doc_url, enabled, created_at, last_rotation}
}

# Transports (как в chimera's openflux.py L405 + WPP wpp_openflux.py)
VALID_TRANSPORTS = ("yandex", "vyandex", "cupsonline", "oneme", "mailru")


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _is_root() -> bool:
    return os.geteuid() == 0


def _run(cmd: list[str], *, capture: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=capture, text=True,
                          timeout=timeout, check=False)


def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _mask_doc_url(url: str) -> str:
    """Маскирует doc_url — оставляет host + path без query (?sk=...)."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception:
        return "<masked>"


def _validate_name(name: str) -> tuple[bool, str]:
    """Валидирует имя профиля: 1-32 символа, [a-z0-9-], lowercase."""
    if not name or not 1 <= len(name) <= 32:
        return False, "Имя должно быть 1-32 символа"
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*[a-z0-9]|[a-z0-9]", name):
        return False, "Только строчные латинские буквы, цифры и дефис"
    if name in ("default", "all", "service"):  # зарезервировано
        return False, f"Имя '{name}' зарезервировано"
    return True, ""


def _validate_doc_url(url: str, transport: str = "yandex") -> tuple[bool, str]:
    """Базовая валидация URL."""
    if not url:
        return False, "URL обязателен"
    try:
        parsed = urlparse(url)
        if not parsed.scheme in ("http", "https"):
            return False, "URL должен быть http(s)://"
        if not parsed.netloc:
            return False, "Некорректный host"
        if len(url) > 4096:
            return False, "URL слишком длинный (>4096 символов)"
        return True, ""
    except Exception as exc:
        return False, f"Некорректный URL: {exc}"


def _gen_transport_key() -> str:
    """32 random bytes → base64 (AES-256-GCM key)."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _profile_dir(name: str) -> Path:
    return OPENFLUX_DIR / name


def _profile_env_file(name: str) -> Path:
    return _profile_dir(name) / "openflux.env"


def _profile_key_file(name: str) -> Path:
    return _profile_dir(name) / "transport.key"


def _profile_bundle_file(name: str) -> Path:
    return _profile_dir(name) / "client-bundle.txt"


def _service_name(name: str) -> str:
    return f"openflux@{name}"


def _ensure_template_unit() -> tuple[bool, str]:
    """Убеждается что /etc/systemd/system/openflux@.service существует.
    Создаёт если нет — minimal template с EnvironmentFile per-profile.
    """
    if TEMPLATE_UNIT.exists():
        return True, "exists"
    if not _is_root():
        return False, "Требуется root для создания template unit"
    TEMPLATE_UNIT.parent.mkdir(parents=True, exist_ok=True)
    # NB: ExecStart использует /opt/openflux/universal-bypass-tool (как в
    # chimera/modules/openflux.py L146 _BIN). Если bin в другом месте —
    # template можно подправить руками.
    unit = """[Unit]
Description=OpenFlux profile %i (multi-profile)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/openflux/%i/openflux.env
ExecStart=/opt/openflux/universal-bypass-tool
WorkingDirectory=/etc/openflux/%i
Restart=on-failure
RestartSec=5
User=root
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ReadWritePaths=/etc/openflux/%i /var/log

[Install]
WantedBy=multi-user.target
"""
    try:
        TEMPLATE_UNIT.write_text(unit)
        TEMPLATE_UNIT.chmod(0o644)
        _run(["systemctl", "daemon-reload"], timeout=15)
        return True, "created"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# ─── STATE LOAD/SAVE ─────────────────────────────────────────────────────────

def _load_state() -> dict:
    """Загружает state. Возвращает DEFAULT_STATE если файла нет."""
    try:
        data = proto_load_state(STATE_FILE, defaults=DEFAULT_STATE)
        if not isinstance(data, dict):
            return dict(DEFAULT_STATE)
        if "profiles" not in data or not isinstance(data["profiles"], dict):
            data["profiles"] = {}
        return data
    except Exception:
        return dict(DEFAULT_STATE)


def _save_state(data: dict) -> None:
    """Атомарно сохраняет state."""
    try:
        proto_save_state(STATE_FILE, data, name="openflux_profiles.json")
    except Exception as exc:
        import sys as _sys
        print(f"[WPP-OPENFLUX-PROFILES] save failed: {type(exc).__name__}: {exc}",
              file=_sys.stderr, flush=True)


# ─── PUBLIC API ──────────────────────────────────────────────────────────────

def profile_states() -> list[dict]:
    """
    Возвращает список всех профилей (без секретов). Каждый профиль:
        {
            "name": str,
            "transport": str,
            "enabled": bool,           # вычисляется через systemctl is-active
            "doc_url_masked": str,
            "created_at": ISO8601 | "",
            "last_rotation": ISO8601 | "",
            "bridge_active": bool,     # deprecated — оставлено для UI
            "service_active": bool,    # alias для enabled
        }
    """
    state = _load_state()
    out: list[dict] = []
    for name, p in state.get("profiles", {}).items():
        enabled = _is_profile_active(name)
        out.append({
            "name":            name,
            "transport":       p.get("transport", ""),
            "enabled":         enabled,
            "service_active":  enabled,
            "doc_url_masked":  _mask_doc_url(p.get("doc_url", "")),
            "created_at":      p.get("created_at", ""),
            "last_rotation":   p.get("last_rotation", ""),
            "bridge_active":   enabled,  # deprecated alias
        })
    return out


def list_profiles() -> list[dict]:
    """Alias для profile_states()."""
    return profile_states()


def get_profile_detail(name: str) -> dict | None:
    """
    Возвращает детальную информацию о профиле (без секретов):
        {
            "name": str,
            "transport": str,
            "enabled": bool,
            "doc_url_masked": str,
            "created_at": ISO8601,
            "last_rotation": ISO8601,
            "client_bundle_path": str,    # путь к client-bundle.txt (без содержимого)
            "env_file_path": str,
            "key_file_path": str,
        }
    """
    state = _load_state()
    p = state.get("profiles", {}).get(name)
    if not p:
        return None
    enabled = _is_profile_active(name)
    return {
        "name":                name,
        "transport":           p.get("transport", ""),
        "enabled":             enabled,
        "doc_url_masked":      _mask_doc_url(p.get("doc_url", "")),
        "created_at":          p.get("created_at", ""),
        "last_rotation":       p.get("last_rotation", ""),
        "client_bundle_path":  str(_profile_bundle_file(name)),
        "env_file_path":       str(_profile_env_file(name)),
        "key_file_path":       str(_profile_key_file(name)),
    }


def _is_profile_active(name: str) -> bool:
    """systemctl is-active --quiet openflux@<name>."""
    try:
        r = _run(["systemctl", "is-active", "--quiet", _service_name(name)],
                 timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def create_profile(name: str, transport: str = "yandex",
                   doc_url: str = "") -> tuple[bool, str]:
    """
    Создаёт новый профиль (disabled by default).
    Steps:
      1. Validate name + transport + doc_url.
      2. Ensure /etc/openflux/<name>/ exists.
      3. Generate transport key (base64 32 bytes).
      4. Write env file, key file.
      5. Add to state.profiles.
    NB: не запускает сервис — для этого отдельно set_enabled(name, True).
    """
    if not _is_root():
        return False, "Требуется root"
    ok, msg = _validate_name(name)
    if not ok:
        return False, msg
    if transport not in VALID_TRANSPORTS:
        return False, f"transport должен быть один из: {', '.join(VALID_TRANSPORTS)}"
    ok, msg = _validate_doc_url(doc_url, transport)
    if not ok:
        return False, msg

    state = _load_state()
    if name in state.get("profiles", {}):
        return False, f"Профиль '{name}' уже существует"
    if len(state.get("profiles", {})) >= 32:
        return False, "Максимум 32 профиля"

    # Ensure template unit exists
    ok, msg = _ensure_template_unit()
    if not ok:
        return False, f"template unit: {msg}"

    # Create per-profile dir
    pdir = _profile_dir(name)
    try:
        pdir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return False, f"mkdir {pdir}: {exc}"

    # Generate transport key
    key = _gen_transport_key()
    key_file = _profile_key_file(name)
    try:
        key_file.write_text(key)
        key_file.chmod(0o600)
    except Exception as exc:
        return False, f"write key: {exc}"

    # Write env file
    env_content = f"""# OpenFlux profile: {name}
# Auto-generated by chimera.modules.openflux_profiles
WPP_PROFILE_NAME={name}
OPENFLUX_TRANSPORT={transport}
OPENFLUX_DOC_URL={doc_url}
OPENFLUX_TRANSPORT_KEY={key}
"""
    try:
        env_file = _profile_env_file(name)
        env_file.write_text(env_content)
        env_file.chmod(0o600)
    except Exception as exc:
        return False, f"write env: {exc}"

    # Update state
    state.setdefault("profiles", {})[name] = {
        "transport":       transport,
        "doc_url":         doc_url,
        "enabled":         False,
        "created_at":      _now_iso(),
        "last_rotation":   _now_iso(),
    }
    _save_state(state)

    return True, f"Профиль '{name}' создан (disabled). Включите через set_enabled('{name}', True)"


def set_enabled(name: str, enable: bool) -> tuple[bool, str]:
    """Включает/выключает профиль через systemctl."""
    if not _is_root():
        return False, "Требуется root"
    state = _load_state()
    if name not in state.get("profiles", {}):
        return False, f"Профиль '{name}' не найден"

    svc = _service_name(name)
    try:
        if enable:
            r = _run(["systemctl", "enable", "--now", svc], timeout=30)
        else:
            r = _run(["systemctl", "disable", "--now", svc], timeout=30)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "").strip()[:500]
            return False, err or f"systemctl exit={r.returncode}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"

    # Update state
    state["profiles"][name]["enabled"] = enable
    _save_state(state)

    return True, f"Профиль '{name}' {'включён' if enable else 'выключен'}"


def rotate_key(name: str) -> tuple[bool, str]:
    """Перегенерирует transport key + restart service если активен."""
    if not _is_root():
        return False, "Требуется root"
    state = _load_state()
    if name not in state.get("profiles", {}):
        return False, f"Профиль '{name}' не найден"

    new_key = _gen_transport_key()
    key_file = _profile_key_file(name)
    try:
        key_file.write_text(new_key)
        key_file.chmod(0o600)
    except Exception as exc:
        return False, f"write key: {exc}"

    # Update env file (regenerate)
    p = state["profiles"][name]
    env_content = f"""# OpenFlux profile: {name}
# Auto-generated by chimera.modules.openflux_profiles
# Last rotation: {_now_iso()}
WPP_PROFILE_NAME={name}
OPENFLUX_TRANSPORT={p.get('transport','yandex')}
OPENFLUX_DOC_URL={p.get('doc_url','')}
OPENFLUX_TRANSPORT_KEY={new_key}
"""
    try:
        env_file = _profile_env_file(name)
        env_file.write_text(env_content)
        env_file.chmod(0o600)
    except Exception as exc:
        return False, f"write env: {exc}"

    # Restart if active
    if _is_profile_active(name):
        _run(["systemctl", "restart", _service_name(name)], timeout=30)

    # Update state
    state["profiles"][name]["last_rotation"] = _now_iso()
    _save_state(state)

    return True, f"Ключ rotated для '{name}' ({new_key[:8]}...)"


def delete_profile(name: str) -> tuple[bool, str]:
    """Удаляет профиль: stop+disable systemd + rm dir + drop from state."""
    if not _is_root():
        return False, "Требуется root"
    state = _load_state()
    if name not in state.get("profiles", {}):
        return False, f"Профиль '{name}' не найден"

    svc = _service_name(name)
    # Stop+disable (silent если не активен)
    _run(["systemctl", "disable", "--now", svc], timeout=30)

    # Remove per-profile dir
    pdir = _profile_dir(name)
    try:
        if pdir.exists():
            shutil.rmtree(pdir, ignore_errors=True)
    except Exception as exc:
        return False, f"rmtree {pdir}: {exc}"

    # Drop from state
    state["profiles"].pop(name, None)
    _save_state(state)

    return True, f"Профиль '{name}' удалён"


def migrate_legacy_single_profile() -> tuple[bool, str]:
    """
    Миграция single-profile openflux.json → profiles['default'].
    Idempotent: если default уже есть в profiles, return.
    """
    state = _load_state()
    if "default" in state.get("profiles", {}):
        return True, "default already migrated"

    legacy_state_file = Path("/var/lib/xray-installer/openflux.json")
    if not legacy_state_file.exists():
        return False, "legacy openflux.json not found, nothing to migrate"

    try:
        legacy = json.loads(legacy_state_file.read_text())
    except Exception as exc:
        return False, f"read legacy: {exc}"

    transport = legacy.get("transport", "yandex")
    doc_url = legacy.get("doc_url", "")
    if not doc_url:
        return False, "legacy has no doc_url"

    # Create 'default' profile via create_profile
    ok, msg = create_profile("default", transport, doc_url)
    if not ok:
        return False, f"create default: {msg}"

    # If legacy openflux.service is active, enable 'default'
    try:
        r = _run(["systemctl", "is-active", "--quiet", "openflux"], timeout=5)
        if r.returncode == 0:
            # Legacy is active — disable legacy, enable 'default'
            _run(["systemctl", "disable", "--now", "openflux"], timeout=30)
            set_enabled("default", True)
    except Exception:
        pass

    return True, "migrated legacy → profiles.default"


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: openflux_profiles.py [list|create|enable|disable|rotate|delete|detail|migrate]",
              file=sys.stderr)
        return 1
    cmd = sys.argv[1]
    if cmd == "list":
        import json as _json
        print(_json.dumps(profile_states(), indent=2, ensure_ascii=False))
        return 0
    elif cmd == "create":
        if len(sys.argv) < 4:
            print("Usage: create <name> [transport] <doc_url>", file=sys.stderr)
            return 1
        name = sys.argv[2]
        transport = sys.argv[3] if len(sys.argv) > 4 else "yandex"
        doc_url = sys.argv[4] if len(sys.argv) > 4 else sys.argv[3]
        if len(sys.argv) == 4:
            transport = "yandex"
            doc_url = sys.argv[3]
        ok, msg = create_profile(name, transport, doc_url)
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "enable":
        ok, msg = set_enabled(sys.argv[2], True)
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "disable":
        ok, msg = set_enabled(sys.argv[2], False)
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "rotate":
        ok, msg = rotate_key(sys.argv[2])
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "delete":
        ok, msg = delete_profile(sys.argv[2])
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "detail":
        d = get_profile_detail(sys.argv[2])
        if d is None:
            print("Not found")
            return 1
        import json as _json
        print(_json.dumps(d, indent=2, ensure_ascii=False))
        return 0
    elif cmd == "migrate":
        ok, msg = migrate_legacy_single_profile()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
