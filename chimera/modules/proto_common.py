"""
chimera/modules/proto_common.py
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
  • proto_ipt_persist()                                 — save nftables ruleset
  • proto_ipt_rule_exists(table, chain, args)           — check rule exists
  • proto_get_latest_version(github_api_url, strip_v=False)
                                                         — latest GitHub release tag
  • proto_get_installed_version(binary_path, version_arg="--version",
                                 strip_v=False)          — installed binary version

Class:
  • ProtoCancelled — raised by proto_ask(c=True). Each module aliases
    ``_Cancelled = ProtoCancelled`` so existing ``except _Cancelled:`` and
    ``raise _Cancelled`` code works unchanged.

Миграция на nftables (этап 1.7, migration-engineer-protocols):
  • proto_ipt_persist() — теперь делегирует в nft_persist() из nft_common.
    Сохраняет весь ruleset в /etc/nftables.conf (замена netfilter-persistent
    save / iptables-save > rules.v4). Имя сохранено для совместимости с
    8 протокольными модулями, импортирующими его через `from proto_common
    import proto_ipt_persist`.
  • proto_ipt_rule_exists(table, chain, args) — теперь извлекает --comment
    из args (если есть) или строит comment из proto/port для OPEN_PORT
    паттерна (`-p X --dport Y -j ACCEPT` → comment="chimera-open-port-X-Y"),
    и проверяет через nft_rule_exists(comment=...). Возвращает False если
    ни comment, ни proto/port не извлечены.

NOT extracted (kept module-local because the logic is genuinely different
per protocol — different systemd unit content, different state fields,
different cleanup steps, different client guides, different nftables
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

# Ленивый импорт nft_common / nft_constants — избегаем циклических зависимостей
# при импорте proto_common из других модулей. Делегируем фактические вызовы
# в функции-обёртки, чтобы import-time не падал если nft_common ещё не
# инициализирован.


# ══════════════════════════════════════════════════════════════════════════════
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# ══════════════════════════════════════════════════════════════════════════════
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


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
#  NFTABLES PERSISTENCE (мигрировано с iptables, этап 1.7)
# ══════════════════════════════════════════════════════════════════════════════
def proto_ipt_persist() -> None:
    """Persist current nftables ruleset so it survives a reboot.

    Мигрировано с iptables (этап 1.7). Заменяет:
      • ``netfilter-persistent save`` (Debian/Ubuntu с iptables-persistent)
      • ``iptables-save > /etc/iptables/rules.v4``

    Теперь делегирует в ``nft_persist()`` из nft_common.py — сохраняет весь
    ruleset в ``/etc/nftables.conf`` через ``nft list ruleset > /etc/nftables.conf``.
    При ребуте системы встроенный ``nftables.service`` (Debian/Ubuntu package)
    читает этот файл через ``nft -f`` и восстанавливает ВСЕ правила Chimera.

    Имя функции сохранено для совместимости с 8 протокольными модулями,
    импортирующими его как ``from proto_common import proto_ipt_persist``.
    Call sites (mieru/naiveproxy/fptn/trusttunnel/turnable/turntunnel/
    wdtt/webdav_tunnel) не меняют сигнатуру — только внутренняя реализация.
    """
    try:
        from .nft_common import nft_persist, nft_persist_enable_systemd
        nft_persist()
        nft_persist_enable_systemd()
    except Exception:
        # Silent fallback — proto_ipt_persist historically был best-effort
        # (subprocess.run сам не бросал). Сохраняем семантику.
        pass


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
            headers={"User-Agent": "Chimera-Project"},
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


def proto_ipt_rule_exists(table: str, chain: str, args: list) -> bool:
    """Проверяет наличие nft-правила через ``nft_rule_exists(comment=...)``.

    Мигрировано с iptables (этап 1.7). Заменяет вызов
    ``iptables -t {table} -C {chain} {args}`` на nftables-эквивалент.

    Возвращает True если правило существует, False — если нет.
    Все протокольные модули (wdtt, mieru, turnable, turntunnel, mtproto,
    fptn, naiveproxy, webdav_tunnel, trusttunnel) делегируют сюда свои
    _ipt_rule_exists, собирая table/chain/args под свой кейс.

    Стратегия извлечения comment (по приоритету):
      1. ``--comment <tag>`` в args (если caller явно передал) → поиск по tag.
      2. ``-p X --dport Y -j ACCEPT`` паттерн (OPEN_PORT) → строит comment
         ``chimera-open-port-X-Y`` (соответствует nft_open_port convention).
      3. ``-d NET -p tcp -j REDIRECT --to-port PORT`` паттерн (NAT REDIRECT
         для Telegram tproxy) → строит comment ``mtproto-tproxy``.
      4. ``-m owner --uid-owner UID -j RETURN`` паттерн (tproxy bypass) →
         comment ``telemt-tproxy-bypass``.
      5. ``-p tcp --dport PORT -j RETURN`` паттерн (ME-port bypass) →
         comment ``mtproto-me-return-PORT``.
      6. Если ничего не извлечено → возвращает False (defensive).

    Map iptables table/chain → nft chain name:
      ``filter``/``INPUT`` → ``input`` в inet chimera
      ``filter``/``OUTPUT`` → ``output``
      ``nat``/``OUTPUT`` → ``output`` (nat hook)
      ``nat``/``PREROUTING`` → ``prerouting``
      ``nat``/``POSTROUTING`` → ``postrouting``
      ``mangle``/``PREROUTING`` → ``mangle_forward``
      ``mangle``/``OUTPUT`` → ``mangle_output``

    Возвращает False при любой ошибке (nft не установлен, нет прав, и т.п.) —
    это безопасно для вызывающих функций: они используют результат только для
    решения "добавлять ли правило". Аналогично iptables -C rc=1 (правило не
    существует) трактуется как False.
    """
    try:
        from .nft_common import nft_rule_exists
        from .nft_constants import (
            NFT_TABLE_NAME, NFT_TABLE_FAMILY,
            NFT_CHAIN_PREROUTING, NFT_CHAIN_POSTROUTING,
            NFT_CHAIN_MANGLE_OUTPUT, NFT_CHAIN_MANGLE_FORWARD,
        )

        # Map iptables table/chain → nft chain name (lowercase).
        _NFT_CHAIN_MAP = {
            ("filter", "INPUT"):       "input",
            ("filter", "OUTPUT"):      "output",
            ("filter", "FORWARD"):     "forward",
            ("nat",   "INPUT"):        "input",
            ("nat",   "OUTPUT"):       "output",
            ("nat",   "PREROUTING"):   NFT_CHAIN_PREROUTING,
            ("nat",   "POSTROUTING"):  NFT_CHAIN_POSTROUTING,
            ("mangle", "INPUT"):       "input",
            ("mangle", "OUTPUT"):      NFT_CHAIN_MANGLE_OUTPUT,
            ("mangle", "FORWARD"):     NFT_CHAIN_MANGLE_FORWARD,
            ("mangle", "PREROUTING"):  NFT_CHAIN_MANGLE_FORWARD,
            ("mangle", "POSTROUTING"): NFT_CHAIN_MANGLE_FORWARD,
        }
        nft_chain = _NFT_CHAIN_MAP.get((table, chain), chain.lower())

        # 1) Извлекаем --comment (если caller явно передал)
        comment = None
        for i, arg in enumerate(args):
            if arg == "--comment" and i + 1 < len(args):
                comment = args[i + 1]
                break

        # 2) NAT REDIRECT pattern: -d NET -p tcp -j REDIRECT --to-port PORT
        #    (проверяем ПЕРВЫМ из patterns, т.к. -p X --dport Y может входить
        #    в состав этого правила как часть `-p tcp`, но действие — REDIRECT,
        #    а не ACCEPT. Поэтому OPEN_PORT pattern должен идти ПОСЛЕ REDIRECT.)
        if comment is None:
            has_redirect = ("-j" in args and "REDIRECT" in args)
            has_to_port = "--to-port" in args
            if has_redirect and has_to_port:
                # Mtproto tproxy REDIRECT — все правила имеют один comment tag.
                comment = "mtproto-tproxy"

        # 3) RETURN rule for uid-owner (tproxy bypass for xray UID)
        if comment is None:
            has_owner = "--uid-owner" in args
            has_return = ("-j" in args and "RETURN" in args)
            if has_owner and has_return:
                comment = "telemt-tproxy-bypass"

        # 4) RETURN rule for ME-port (mtproto ME-bypass)
        if comment is None:
            has_return = ("-j" in args and "RETURN" in args)
            has_dport = "--dport" in args
            if has_return and has_dport and "-p" in args:
                # Извлекаем dport для per-port comment
                dport = None
                for i, arg in enumerate(args):
                    if arg == "--dport" and i + 1 < len(args):
                        dport = args[i + 1]
                        break
                if dport:
                    comment = f"mtproto-me-return-{dport}"

        # 5) OPEN_PORT pattern: `-p X --dport Y -j ACCEPT` (проверяем ПОСЛЕ
        #    специфичных patterns, чтобы RETURN/REDIRECT не захватывались).
        if comment is None:
            proto = dport = None
            has_accept = ("-j" in args and "ACCEPT" in args)
            for i, arg in enumerate(args):
                if arg == "-p" and i + 1 < len(args):
                    proto = args[i + 1].lower()
                elif arg == "--dport" and i + 1 < len(args):
                    dport = args[i + 1]
            if proto and dport and has_accept:
                # Это OPEN_PORT pattern (nft_open_port convention).
                comment = f"chimera-open-port-{proto}-{dport}"

        # 6) Ни один паттерн не распознан — возвращаем False (defensive).
        if comment is None:
            return False

        return nft_rule_exists(
            table=NFT_TABLE_NAME, chain=nft_chain,
            comment=comment, family=NFT_TABLE_FAMILY,
        )
    except Exception:
        # Любой сбой (nft не установлен, нет прав, и т.п.) — считаем что
        # правила нет. Аналогично старой iptables-реализации: try/except
        # вокруг _run, return False on failure.
        return False
