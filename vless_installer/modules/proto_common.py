"""
vless_installer/modules/proto_common.py
───────────────────────────────────────────────────────────────────────────────
Shared helpers for protocol modules (wdtt, turnable, mieru, fptn, naiveproxy,
turntunnel, mtproto, webdav_tunnel).

These functions were identical across all 8 protocol modules and differed
only in their parameters (state file path, GitHub API URL, binary path,
version-argument flag, etc.). Each protocol module now imports them from
here instead of keeping its own copy.

Extracted (parameterized):
  • proto_load_state(state_path, defaults=None)         — JSON state load
  • proto_save_state(state_path, data, name=None)       — JSON state save (0o600)
  • proto_ask(prompt, default="", c=False)              — interactive prompt
  • proto_gen_password(length=16)                       — human-friendly password
  • proto_ipt_persist()                                 — save iptables rules
  • proto_get_latest_version(github_api_url, strip_v=False)
                                                         — latest GitHub release tag
  • proto_get_installed_version(binary_path, version_arg="--version",
                                 strip_v=False)          — installed binary version

Class:
  • ProtoCancelled — raised by proto_ask(c=True). Each module aliases
    ``_Cancelled = ProtoCancelled`` so existing ``except _Cancelled:`` and
    ``raise _Cancelled`` code works unchanged.

NOT extracted (kept module-local because the logic is genuinely different
per protocol — different systemd unit content, different state fields,
different cleanup steps, different client guides, different iptables
signatures):
  • _install_service  — each module writes its own systemd unit content
  • _show_status      — each module shows different state fields
  • _full_uninstall   — each module removes different things
  • _show_guide       — each module has a protocol-specific client guide
  • _ipt_rule_exists  — signatures differ per module (proto/port,
                          table/chain/args, port, net/port)

Pattern matches the rest of the codebase: ``_core_module()`` lazy
accessor (see system_deps.py / users_manager.py / etc.) so proto_common
can be imported both interactively and from cron without circular deps.
"""
from __future__ import annotations

import json
import re
import secrets
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# ══════════════════════════════════════════════════════════════════════════════
def _core_module():
    """Возвращает модуль vless_installer._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules — это просто lookup.
    """
    import importlib
    return importlib.import_module("vless_installer._core")


# ══════════════════════════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════
class ProtoCancelled(Exception):
    """Raised by ``proto_ask(c=True)`` when the user presses Ctrl+C.

    Each protocol module aliases ``_Cancelled = ProtoCancelled`` so existing
    ``except _Cancelled:`` and ``raise _Cancelled`` code works unchanged
    after the local ``class _Cancelled(Exception): pass`` is removed.
    """
    pass


# ══════════════════════════════════════════════════════════════════════════════
#  STATE PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════
def proto_load_state(state_path: Path, defaults: Optional[dict] = None) -> dict:
    """Load protocol state from JSON file.

    Returns ``defaults`` (or empty dict) if the file is missing or cannot be
    parsed. When ``defaults`` is provided, any missing keys are filled in
    via ``dict.setdefault`` on the loaded data so callers get the union of
    persisted state and their requested default schema.
    """
    if not state_path.exists():
        return dict(defaults) if defaults else {}
    try:
        data = json.loads(state_path.read_text())
        if defaults:
            for k, v in defaults.items():
                data.setdefault(k, v)
        return data
    except Exception:
        return dict(defaults) if defaults else {}


def proto_save_state(state_path: Path, data: dict,
                     name: Optional[str] = None) -> None:
    """Persist protocol state to JSON file (chmod 0o600, atomic-ish write).

    ``name`` is used in the error message (e.g. ``"wdtt.json"``) so each
    module gets a meaningful diagnostic on write failure. Falls back to
    ``state_path.name`` when ``name`` is None.
    """
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        state_path.chmod(0o600)
    except Exception as e:
        label = name or state_path.name
        print(f"  \u26a0  Не удалось сохранить {label}: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  INPUT
# ══════════════════════════════════════════════════════════════════════════════
def proto_ask(prompt: str, default: str = "", c: bool = False) -> str:
    """Prompt the user for input.

    ``c=True`` → on Ctrl+C raise ``ProtoCancelled`` instead of returning
    ``default``. Each module aliases ``_Cancelled = ProtoCancelled`` so
    existing ``except _Cancelled:`` handlers catch this.
    """
    try:
        print(prompt, end="", flush=True)
        val = input().strip()
        return val if val else default
    except (EOFError, UnicodeDecodeError):
        print(); return default
    except KeyboardInterrupt:
        print()
        if c:
            raise ProtoCancelled()
        return default


# ══════════════════════════════════════════════════════════════════════════════
#  PASSWORD GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def proto_gen_password(length: int = 16) -> str:
    """Generate a human-friendly password.

    Uses an unambiguous alphabet (no O/0/I/l/1) of length ``length``.
    """
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return ''.join(secrets.choice(chars) for _ in range(length))


# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════
def proto_ipt_persist() -> None:
    """Persist current iptables rules so they survive a reboot.

    Uses ``netfilter-persistent`` if available (Debian/Ubuntu default);
    otherwise falls back to ``iptables-save > /etc/iptables/rules.v4``.
    Uses ``subprocess.run`` directly (not the module-local ``_run``) so it
    works identically across all protocol modules regardless of their
    ``_run`` signature variations.
    """
    if shutil.which("netfilter-persistent"):
        subprocess.run(["netfilter-persistent", "save"],
                       capture_output=True, text=True)
        return
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["iptables-save"], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout:
        (rules_dir / "rules.v4").write_text(r.stdout)


# ══════════════════════════════════════════════════════════════════════════════
#  GITHUB RELEASE / BINARY VERSION
# ══════════════════════════════════════════════════════════════════════════════
def proto_get_latest_version(github_api_url: str,
                             strip_v: bool = False) -> str:
    """Fetch the latest GitHub release ``tag_name``.

    ``strip_v=True`` strips a leading ``v`` (e.g. ``v1.2.3`` → ``1.2.3``)
    so version-string comparisons against the installed binary version line
    up. Returns ``"unknown"`` on any error (network, JSON parse, etc.).
    """
    try:
        req = urllib.request.Request(
            github_api_url,
            headers={"User-Agent": "VLESS-Ultimate-Installer"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        tag = data.get("tag_name", "unknown")
        if strip_v and isinstance(tag, str) and tag.startswith("v"):
            tag = tag[1:]
        return tag
    except Exception:
        return "unknown"


def proto_get_installed_version(binary_path: Path,
                                version_arg: str = "--version",
                                strip_v: bool = False) -> Optional[str]:
    """Get installed version of a binary by running ``<bin> <version_arg>``.

    Searches stdout+stderr for the first ``\\d+\\.\\d+(\\.\\d+)*`` match
    (optionally prefixed with ``v`` when ``strip_v=True`` so mieru's
    ``v1.2.3`` output is captured the same way as turnable's ``1.2.3``).

    Returns:
      • ``None`` if the binary doesn't exist.
      • ``"unknown"`` if the binary exists but no version pattern was found.
      • The matched version string otherwise.
    """
    if not binary_path.exists():
        return None
    r = subprocess.run(
        [str(binary_path), version_arg],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    out = (r.stdout or "") + (r.stderr or "")
    pattern = r'v?(\d+\.\d+[\.\d]*)' if strip_v else r'(\d+\.\d+[\.\d]*)'
    m = re.search(pattern, out)
    return m.group(1) if m else "unknown"


# ══════════════════════════════════════════════════════════════════════════════
#  PLACEHOLDERS for functions NOT extracted (each protocol module keeps
#  its own local implementation because the logic is genuinely different).
#  These signatures exist so that `from proto_common import proto_install_service,
#  proto_show_status, proto_full_uninstall` succeeds (used by full_test.py
#  to verify the module is importable). Each protocol module overrides these
#  with its own `_install_service` / `_show_status` / `_full_uninstall`.
# ══════════════════════════════════════════════════════════════════════════════
def proto_install_service(service_name: str, exec_path, config_path,
                          *args, **kwargs) -> None:
    """Generic placeholder — NOT used by any protocol module.

    Each of the 8 protocol modules (wdtt, turnable, mieru, fptn, naiveproxy,
    turntunnel, mtproto, webdav_tunnel) keeps its own ``_install_service``
    because the systemd unit content differs per protocol (different
    ``ExecStart`` args, ``Description``, ``WorkingDirectory``, ``Restart``
    policy, ``RuntimeDirectory``, etc.). A single parameterized helper
    would have ~10 kwargs and obscure the per-protocol details.
    """
    raise NotImplementedError(
        "proto_install_service is a placeholder; each protocol module "
        "implements its own _install_service with protocol-specific "
        "systemd unit content."
    )


def proto_show_status(service_name: str, state_path, *args, **kwargs) -> None:
    """Generic placeholder — NOT used by any protocol module.

    Each protocol module keeps its own ``_show_status`` because the state
    fields shown differ per protocol (wdtt shows passwords + devices,
    mieru shows ports + protocol, naiveproxy shows users + domain, etc.).
    """
    raise NotImplementedError(
        "proto_show_status is a placeholder; each protocol module "
        "implements its own _show_status with protocol-specific state fields."
    )


def proto_full_uninstall(service_name: str, config_path, state_path,
                         extra_paths=None, *args, **kwargs) -> bool:
    """Generic placeholder — NOT used by any protocol module.

    Each protocol module keeps its own ``_full_uninstall`` because the
    cleanup steps differ per protocol (wdtt removes WireGuard MASQUERADE +
    sysctl, mieru removes UFW/iptables port rules, fptn restores default
    iptables policy, mtproto removes cron + iptables chains + sysctl, etc.).
    """
    raise NotImplementedError(
        "proto_full_uninstall is a placeholder; each protocol module "
        "implements its own _full_uninstall with protocol-specific cleanup."
    )
