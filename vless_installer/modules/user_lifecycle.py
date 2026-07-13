"""
vless_installer/modules/user_lifecycle.py
───────────────────────────────────────────────────────────────────────────────
Единый модуль для операций жизненного цикла пользователя across все протоколы.

ЗАДАЧА МОДУЛЯ
=============
Централизовать все операции add/remove/block/unblock/update_limits и
синхронизировать их сразу во всех поддерживаемых протоколах:
  • VLESS / Xray REALITY / xHTTP
  • AWG (AmneziaWG standalone, включая cascade)
  • Hysteria2 (shared password — нет per-user, но есть service-level enable/disable)
  • Mieru (mita)
  • MTProto / Telemt
  • NaiveProxy (caddy-naive)
  • FPTN
  • sing-box (ShadowTLS / AnyTLS / TUIC / Trojan / VLESS-WS-CDN)

АРХИТЕКТУРА
===========
1. PROTOCOL ADAPTERS — тонкие обёртки над существующими протокол-специфичными
   функциями (НЕ дублируют логику генерации конфигов, только вызывают их).
   Каждый adapter реализует единый интерфейс:
     add(email, uuid, name) -> bool
     remove(identifier) -> bool
     block(identifier) -> bool   # опционально, если протокол поддерживает
     unblock(identifier) -> bool # опционально

2. TRANSACTIONAL COORDINATOR — оркестрирует multi-protocol операции:
     add_user(email, protocols, ttl, traffic_limit)
     remove_user(email, protocols)
     block_user(email, reason)
     unblock_user(email)
     update_limits(email, ttl, traffic_limit)
   Делает snapshot state-файлов перед операцией, прикладывает изменения
   последовательно, при ошибке хотя бы одного протокола — откатывает ВСЁ.

3. CRON ENTRYPOINTS — единая точка `run_cleanup()` для cron, плюс тонкие
   обёртки для обратной совместимости с существующими CLI-флагами.

IDENTITY MODEL
==============
Канонический идентификатор пользователя в системе — это (email, uuid) пара
из /etc/xray/users.json. Остальные протоколы связываются через:
  • AWG:        peer.owner_email == vless_user.email
  • sing-box:   inbound.users[].uuid == vless_user.uuid
  • Mieru:      user.username == vless_user.email.split('@')[0]   (convention)
  • MTProto:    user.username == vless_user.email.split('@')[0]   (convention)
  • NaiveProxy: user.username == vless_user.email.split('@')[0]   (convention)
  • FPTN:       user.username == vless_user.email.split('@')[0]   (convention)
  • Hysteria2:  нет per-user (общий пароль) — adapter заглушка

ОБРАТНАЯ СОВМЕСТИМОСТЬ
======================
Существующие функции (_ttl_check_and_expire, _check_traffic_limits_once,
_ttl_block_user, _ttl_unblock_user) остаются как тонкие делегаты к
user_lifecycle — это позволяет всем CLI-флагам и cron-задачам продолжать
работать без изменений.

Публичное API:
    add_user(email, protocols="all", ttl=None, traffic_limit=None, name=None)
    remove_user(email, protocols="all")
    block_user(email, reason="manual")
    unblock_user(email)
    update_limits(email, ttl=None, traffic_limit=None)
    run_cleanup()  # единый cron entrypoint
    check_ttl_expired()  # для обратной совместимости с --ttl-check
    check_traffic_limits()  # для обратной совместимости (новый --traffic-check)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Union, List, Dict, Tuple, Callable


# ── Константы путей к state-файлам (читаем + пишем) ──────────────────────────
_USERS_FILE       = Path("/etc/xray/users.json")
_XRAY_CONFIG_FILE = Path("/etc/xray/config.json")
_STATE_FILE       = Path("/var/lib/xray-installer/state.json")
_TTL_FILE         = Path("/var/lib/xray-installer/ttl_users.json")
_LIMITS_FILE      = Path("/var/lib/xray-installer/traffic_limits.json")
_BLOCKED_FILE     = Path("/var/lib/xray-installer/blocked_users.json")
_AWG_STATE_FILE   = Path("/var/lib/xray-installer/awg_standalone_state.json")
_SINGBOX_STATE_FILE = Path("/var/lib/xray-installer/singbox_state.json")
_MIERU_STATE_FILE   = Path("/var/lib/xray-installer/mieru.json")
_NAIVE_STATE_FILE   = Path("/var/lib/xray-installer/naiveproxy.json")
_FPTN_STATE_FILE    = Path("/var/lib/xray-installer/fptn.json")
_TELEMT_TOML_FILE   = Path("/etc/telemt/telemt.toml")
_FPTN_USERS_LIST    = Path("/etc/fptn/users.list")

# Лог
_LOG_FILE = Path("/var/log/xray-user-lifecycle.log")

# Список всех протоколов, поддерживаемых lifecycle
ALL_PROTOCOLS = ["vless", "awg", "singbox", "mieru", "mtproto", "naiveproxy", "fptn", "hysteria2"]


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core (lazy import)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  ЛОГИРОВАНИЕ
# =============================================================================
def _log(level: str, msg: str) -> None:
    """Логирует в /var/log/xray-user-lifecycle.log и в основной vless-install.log."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [USER-LIFECYCLE] [{level}] {msg}"
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    # Также пишем в основной лог для общей видимости
    try:
        core = _core_module()
        if hasattr(core, "log_to_file"):
            core.log_to_file(level, f"user_lifecycle: {msg}")
    except Exception:
        pass


def _log_op(operation: str, email: str, protocols: List[str],
            success: bool, details: str = "") -> None:
    """Логирует результат операции с указанием затронутых протоколов."""
    status = "OK" if success else "FAIL"
    proto_str = ",".join(protocols) if protocols else "none"
    msg = f"{operation} user={email!r} protocols=[{proto_str}] {status}"
    if details:
        msg += f" :: {details}"
    _log("INFO" if success else "ERROR", msg)


# =============================================================================
#  HELPERS: чтение/запись JSON state-файлов
# =============================================================================
def _read_json(path: Path) -> Union[dict, list]:
    """Безопасное чтение JSON. Возвращает {} для dict или [] для list."""
    try:
        if path.exists():
            data = json.loads(path.read_text())
            return data
    except Exception:
        pass
    return {}


def _read_users() -> list:
    """Читает /etc/xray/users.json. Возвращает [] при ошибке."""
    try:
        if _USERS_FILE.exists():
            data = json.loads(_USERS_FILE.read_text())
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def _write_users(users: list) -> None:
    """Атомарная запись users.json с chmod 0o640."""
    _USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))
    try:
        _USERS_FILE.chmod(0o640)
    except Exception:
        pass


# =============================================================================
#  IDENTITY RESOLUTION
# =============================================================================
def find_user_by_email(email: str, users: Optional[list] = None) -> Optional[dict]:
    """Линейный поиск пользователя по email в users.json."""
    if users is None:
        users = _read_users()
    for u in users:
        if u.get("email", "") == email:
            return u
    return None


def find_user_by_uuid(uuid_str: str, users: Optional[list] = None) -> Optional[dict]:
    """Линейный поиск пользователя по UUID."""
    if users is None:
        users = _read_users()
    for u in users:
        if u.get("uuid", "") == uuid_str:
            return u
    return None


def resolve_user(email: str = "", uuid_str: str = "",
                 users: Optional[list] = None) -> Optional[dict]:
    """Находит пользователя по email или UUID. Возвращает dict или None."""
    if email:
        return find_user_by_email(email, users)
    if uuid_str:
        return find_user_by_uuid(uuid_str, users)
    return None


def _username_from_email(email: str) -> str:
    """Извлекает username для протоколов Mieru/MTProto/NaiveProxy/FPTN
    по конвенции: username = email.split('@')[0].
    """
    return (email or "").split("@")[0].strip()


def _normalize_protocols(protocols: Union[str, List[str]]) -> List[str]:
    """Нормализует список протоколов.
    - "all" → ALL_PROTOCOLS
    - ["vless", "awg"] → как есть
    - "vless" → ["vless"]
    """
    if protocols == "all":
        return list(ALL_PROTOCOLS)
    if isinstance(protocols, str):
        return [protocols.lower()]
    return [p.lower() for p in protocols]


# =============================================================================
#  SNAPSHOT / ROLLBACK для транзакционности
# =============================================================================
class StateSnapshot:
    """
    Snapshot state-файлов перед операцией для отката при сбое.

    Использование:
        snap = StateSnapshot()
        snap.capture([_USERS_FILE, _TTL_FILE, _LIMITS_FILE, ...])
        try:
            # ... применяем изменения ...
            snap.commit()  # забыли snapshot
        except Exception:
            snap.restore()  # откатили всё
            raise
    """

    def __init__(self):
        self._snapshots: Dict[Path, bytes] = {}
        self._captured: bool = False

    def capture(self, paths: List[Path]) -> None:
        """Делает бинарный snapshot всех файлов, которые существуют."""
        for p in paths:
            try:
                if p.exists():
                    self._snapshots[p] = p.read_bytes()
                else:
                    # Запоминаем что файла не было — при restore удалим
                    self._snapshots[p] = None
            except Exception as e:
                _log("WARN", f"snapshot: cannot read {p}: {e}")
                self._snapshots[p] = None
        self._captured = True

    def restore(self) -> None:
        """Восстанавливает все файлы из snapshot."""
        if not self._captured:
            return
        for path, data in self._snapshots.items():
            try:
                if data is None:
                    # Файла не было — удаляем если появился
                    if path.exists():
                        path.unlink()
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    # Восстанавливаем права как у других state-файлов
                    try:
                        if path.name.endswith(".json"):
                            path.chmod(0o600)
                    except Exception:
                        pass
            except Exception as e:
                _log("ERROR", f"restore: cannot write {path}: {e}")
        _log("WARN", "state snapshot restored (rollback completed)")

    def commit(self) -> None:
        """Помечает snapshot как больше не нужный (операция успешна)."""
        self._captured = False
        self._snapshots.clear()


# =============================================================================
#  PROTOCOL ADAPTERS
# =============================================================================
# Каждый adapter реализует статические методы:
#   add(email, uuid, name) -> bool       — добавить пользователя
#   remove(identifier) -> bool            — удалить (identifier = email/uuid/username)
#   block(identifier) -> bool             — заблокировать (если применимо)
#   unblock(identifier) -> bool           — разблокировать (если применимо)
#
# ВАЖНО: adapters НЕ дублируют логику генерации конфигов. Они вызывают
# существующие протокол-специфичные функции (awg_peer_add, singbox_sync_users,
# _users_apply_to_config и т.д.).
# =============================================================================


class VlessAdapter:
    """Adapter для VLESS/Xray — источник правды (users.json + xray config.json)."""

    PROTOCOL_NAME = "vless"

    @staticmethod
    def add(email: str, uuid: str, name: str = "", **kwargs) -> bool:
        """Добавляет пользователя в users.json и применяет к xray config.
        НЕ создаёт UUID — он должен быть передан (администратор или caller).
        """
        try:
            core = _core_module()
            users = core._users_load()
            # Идемпотентность: если уже есть с тем же UUID — noop
            existing = find_user_by_email(email, users)
            if existing:
                if existing.get("uuid") == uuid:
                    _log("INFO", f"vless.add: user {email!r} already exists with same uuid, noop")
                    return True
                _log("ERROR", f"vless.add: user {email!r} exists with different uuid")
                return False
            # Добавляем
            new_user = {
                "uuid":         uuid,
                "email":        email,
                "name":         name or email.split("@")[0],
                "created":      datetime.now(timezone.utc).isoformat(),
                "source":       "user_lifecycle",
                "disabled":     False,
                "disabled_at":  "",
                "blocked":      False,
                "blocked_at":   "",
                "block_reason": "",
            }
            users.append(new_user)
            core._users_save(users)
            # Применяем к xray config + restart
            ok = core._users_apply_to_config(users)
            if not ok:
                _log("ERROR", f"vless.add: _users_apply_to_config failed for {email!r}")
                return False
            return True
        except Exception as e:
            _log("ERROR", f"vless.add: exception for {email!r}: {e}")
            return False

    @staticmethod
    def remove(email: str, **kwargs) -> bool:
        """Удаляет пользователя из users.json и xray config."""
        try:
            core = _core_module()
            users = core._users_load()
            new_users = [u for u in users if u.get("email") != email]
            if len(new_users) == len(users):
                _log("INFO", f"vless.remove: user {email!r} not found, noop")
                return True  # Идемпотентность
            core._users_save(new_users)
            ok = core._users_apply_to_config(new_users)
            if not ok:
                _log("ERROR", f"vless.remove: _users_apply_to_config failed for {email!r}")
                return False
            return True
        except Exception as e:
            _log("ERROR", f"vless.remove: exception for {email!r}: {e}")
            return False

    @staticmethod
    def block(email: str, reason: str = "manual", **kwargs) -> bool:
        """Блокирует: ставит blocked=True, удаляет из xray config, не трогает users.json entry."""
        try:
            core = _core_module()
            users = core._users_load()
            target = find_user_by_email(email, users)
            if not target:
                _log("WARN", f"vless.block: user {email!r} not found, noop")
                return True  # Идемпотентность
            if target.get("blocked") and target.get("block_reason") == reason:
                _log("INFO", f"vless.block: user {email!r} already blocked with same reason, noop")
                return True
            target["blocked"] = True
            target["blocked_at"] = datetime.now(timezone.utc).isoformat()
            target["block_reason"] = reason
            core._users_save(users)
            # Применяем с фильтром blocked
            active = [u for u in users if not u.get("blocked") and not u.get("disabled")]
            ok = core._users_apply_to_config(active)
            if not ok:
                _log("ERROR", f"vless.block: _users_apply_to_config failed for {email!r}")
                return False
            # Пишем в blocked_users.json (для совместимости с существующим TTL-механизмом)
            blocked_db = _read_json(_BLOCKED_FILE)
            if not isinstance(blocked_db, dict):
                blocked_db = {}
            blocked_db[email] = {
                "email":       email,
                "uuid":        target.get("uuid", ""),
                "name":        target.get("name", ""),
                "blocked_at":  target["blocked_at"],
                "reason":      reason,
            }
            _BLOCKED_FILE.parent.mkdir(parents=True, exist_ok=True)
            _BLOCKED_FILE.write_text(json.dumps(blocked_db, indent=2, ensure_ascii=False))
            try:
                _BLOCKED_FILE.chmod(0o600)
            except Exception:
                pass
            return True
        except Exception as e:
            _log("ERROR", f"vless.block: exception for {email!r}: {e}")
            return False

    @staticmethod
    def unblock(email: str, **kwargs) -> bool:
        """Снимает blocked=True, возвращает в xray config."""
        try:
            core = _core_module()
            users = core._users_load()
            target = find_user_by_email(email, users)
            if not target:
                _log("WARN", f"vless.unblock: user {email!r} not found, noop")
                return True
            if not target.get("blocked"):
                _log("INFO", f"vless.unblock: user {email!r} not blocked, noop")
                return True
            target["blocked"] = False
            target["blocked_at"] = ""
            target["block_reason"] = ""
            core._users_save(users)
            active = [u for u in users if not u.get("blocked") and not u.get("disabled")]
            ok = core._users_apply_to_config(active)
            if not ok:
                _log("ERROR", f"vless.unblock: _users_apply_to_config failed for {email!r}")
                return False
            # Удаляем из blocked_users.json
            blocked_db = _read_json(_BLOCKED_FILE)
            if isinstance(blocked_db, dict) and email in blocked_db:
                del blocked_db[email]
                _BLOCKED_FILE.write_text(json.dumps(blocked_db, indent=2, ensure_ascii=False))
            return True
        except Exception as e:
            _log("ERROR", f"vless.unblock: exception for {email!r}: {e}")
            return False


class AwgAdapter:
    """Adapter для AWG (AmneziaWG standalone). Связь через owner_email."""

    PROTOCOL_NAME = "awg"

    @staticmethod
    def add(email: str, uuid: str, name: str = "", **kwargs) -> bool:
        """Добавляет AWG-пира с owner_email=email, name=username из email."""
        try:
            from vless_installer.modules.awg_peers import awg_peer_add
            from vless_installer.modules.awg_state import (
                awgs_state_load, awgs_state_find_peer_by_owner,
            )
            # Проверяем что AWG установлен
            state = awgs_state_load()
            if not state.get("installed"):
                _log("INFO", "awg.add: AWG not installed, skipping (not an error)")
                return True
            # Идемпотентность: если пир уже есть для этого email — noop
            existing = awgs_state_find_peer_by_owner(email)
            if existing:
                _log("INFO", f"awg.add: peer for {email!r} already exists, noop")
                return True
            peer_name = name or _username_from_email(email)
            ok = awg_peer_add(
                name=peer_name,
                expires="",
                psk=False,
                apply=True,
                save_state=True,
                show_qr=False,
                owner_email=email,
            )
            return bool(ok)
        except Exception as e:
            _log("ERROR", f"awg.add: exception for {email!r}: {e}")
            return False

    @staticmethod
    def remove(email: str, **kwargs) -> bool:
        """Удаляет AWG-пир(ы) с owner_email=email."""
        try:
            from vless_installer.modules.awg_peers import awg_peer_remove
            from vless_installer.modules.awg_state import (
                awgs_state_load, awgs_state_find_peer_by_owner,
            )
            state = awgs_state_load()
            if not state.get("installed"):
                return True
            peer = awgs_state_find_peer_by_owner(email)
            if not peer:
                _log("INFO", f"awg.remove: no peer for {email!r}, noop")
                return True
            ok = awg_peer_remove(peer["name"], apply=True, save_state=True)
            return bool(ok)
        except Exception as e:
            _log("ERROR", f"awg.remove: exception for {email!r}: {e}")
            return False

    @staticmethod
    def block(email: str, reason: str = "manual", **kwargs) -> bool:
        """AWG не имеет per-user block — удаляем пира (можно пересоздать при unblock).
        Альтернатива: оставляем пира, но это небезопасно — он продолжит работать.
        Поэтому для AWG block = remove peer.
        """
        _log("INFO", f"awg.block: removing peer for {email!r} (reason={reason})")
        return AwgAdapter.remove(email)

    @staticmethod
    def unblock(email: str, **kwargs) -> bool:
        """AWG: пересоздаём пира (но нам нужен uuid для нового пир-ключа —
        это не нужно для AWG, ключи генерируются заново). Делегируем в add.
        Внимание: это создаст НОВЫЕ ключи, старые — потеряны.
        """
        _log("INFO", f"awg.unblock: re-creating peer for {email!r} (new keys will be generated)")
        return AwgAdapter.add(email, uuid="", name=_username_from_email(email))


class SingboxAdapter:
    """Adapter для sing-box. Связь через UUID."""

    PROTOCOL_NAME = "singbox"

    @staticmethod
    def add(email: str, uuid: str, name: str = "", **kwargs) -> bool:
        """Добавляет UUID во все включённые sing-box inbounds."""
        try:
            from vless_installer.modules.singbox_state import singbox_state_load
            from vless_installer.modules.singbox_users import (
                singbox_state_add_user_to_all_protocols,
            )
            state = singbox_state_load()
            if not state.get("installed"):
                _log("INFO", "singbox.add: sing-box not installed, skipping")
                return True
            if not uuid:
                _log("WARN", "singbox.add: uuid required, skipping")
                return True
            ok = singbox_state_add_user_to_all_protocols(uuid, name or _username_from_email(email))
            return bool(ok)
        except Exception as e:
            _log("ERROR", f"singbox.add: exception for {email!r}: {e}")
            return False

    @staticmethod
    def remove(email: str, uuid: str = "", **kwargs) -> bool:
        """Удаляет UUID из всех sing-box inbounds."""
        try:
            from vless_installer.modules.singbox_state import singbox_state_load
            from vless_installer.modules.singbox_users import (
                singbox_state_remove_user_from_all_protocols,
            )
            state = singbox_state_load()
            if not state.get("installed"):
                return True
            # Если uuid не передан — пытаемся найти через users.json
            if not uuid:
                user = find_user_by_email(email)
                if not user:
                    return True
                uuid = user.get("uuid", "")
            if not uuid:
                return True
            ok = singbox_state_remove_user_from_all_protocols(uuid)
            return bool(ok)
        except Exception as e:
            _log("ERROR", f"singbox.remove: exception for {email!r}: {e}")
            return False

    @staticmethod
    def block(email: str, reason: str = "manual", **kwargs) -> bool:
        """Блокировка sing-box = удаление UUID из inbounds. Аналог remove."""
        _log("INFO", f"singbox.block: removing uuid for {email!r} (reason={reason})")
        return SingboxAdapter.remove(email, **kwargs)

    @staticmethod
    def unblock(email: str, uuid: str = "", **kwargs) -> bool:
        """Разблокировка sing-box = добавление UUID обратно."""
        if not uuid:
            user = find_user_by_email(email)
            if user:
                uuid = user.get("uuid", "")
        return SingboxAdapter.add(email, uuid, **kwargs)


class MieruAdapter:
    """Adapter для Mieru. Связь через username (convention: email.split('@')[0])."""

    PROTOCOL_NAME = "mieru"

    @staticmethod
    def _state() -> dict:
        return _read_json(_MIERU_STATE_FILE)

    @staticmethod
    def _save_state(state: dict) -> None:
        _MIERU_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _MIERU_STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        try:
            _MIERU_STATE_FILE.chmod(0o600)
        except Exception:
            pass

    @staticmethod
    def _apply(state: dict) -> bool:
        """Регенерирует /etc/mita/server.json и перезапускает mita."""
        try:
            from vless_installer.modules.mieru import _build_server_config, _apply_server_config
            cfg = _build_server_config(
                state.get("users", []),
                state.get("port_start", 2012),
                state.get("port_end", 2022),
                state.get("protocol", "TCP"),
                state.get("traffic_pattern"),
            )
            _apply_server_config(cfg)
            return True
        except Exception as e:
            _log("ERROR", f"mieru._apply: {e}")
            return False

    @staticmethod
    def add(email: str, uuid: str = "", name: str = "", **kwargs) -> bool:
        try:
            state = MieruAdapter._state()
            if not state.get("installed"):
                _log("INFO", "mieru.add: Mieru not installed, skipping")
                return True
            username = _username_from_email(email)
            users = state.get("users", [])
            if any(u.get("username") == username for u in users):
                _log("INFO", f"mieru.add: user {username!r} already exists, noop")
                return True
            # Генерируем пароль
            try:
                from vless_installer.modules.proto_common import proto_gen_password
                password = proto_gen_password()
            except Exception:
                import secrets as _s
                password = _s.token_urlsafe(16)
            users.append({"username": username, "password": password})
            state["users"] = users
            MieruAdapter._save_state(state)
            return MieruAdapter._apply(state)
        except Exception as e:
            _log("ERROR", f"mieru.add: exception for {email!r}: {e}")
            return False

    @staticmethod
    def remove(email: str, **kwargs) -> bool:
        try:
            state = MieruAdapter._state()
            if not state.get("installed"):
                return True
            username = _username_from_email(email)
            users = state.get("users", [])
            new_users = [u for u in users if u.get("username") != username]
            if len(new_users) == len(users):
                _log("INFO", f"mieru.remove: user {username!r} not found, noop")
                return True
            state["users"] = new_users
            MieruAdapter._save_state(state)
            return MieruAdapter._apply(state)
        except Exception as e:
            _log("ERROR", f"mieru.remove: exception for {email!r}: {e}")
            return False

    @staticmethod
    def block(email: str, reason: str = "manual", **kwargs) -> bool:
        """Mieru не имеет block — remove."""
        _log("INFO", f"mieru.block: removing user for {email!r} (reason={reason})")
        return MieruAdapter.remove(email)

    @staticmethod
    def unblock(email: str, **kwargs) -> bool:
        """Mieru: пересоздаём с новым паролем."""
        _log("INFO", f"mieru.unblock: re-creating user for {email!r} (new password)")
        return MieruAdapter.add(email)


class NaiveProxyAdapter:
    """Adapter для NaiveProxy. Связь через username."""

    PROTOCOL_NAME = "naiveproxy"

    @staticmethod
    def _state() -> dict:
        return _read_json(_NAIVE_STATE_FILE)

    @staticmethod
    def _save_state(state: dict) -> None:
        _NAIVE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _NAIVE_STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        try:
            _NAIVE_STATE_FILE.chmod(0o600)
        except Exception:
            pass

    @staticmethod
    def _apply(state: dict) -> bool:
        try:
            from vless_installer.modules.naiveproxy import _apply_config
            _apply_config(
                state.get("domain", ""),
                state.get("port", 443),
                state.get("users", []),
                state.get("fake_url", ""),
                state.get("probe_secret", ""),
                state.get("upstream", ""),
            )
            return True
        except Exception as e:
            _log("ERROR", f"naiveproxy._apply: {e}")
            return False

    @staticmethod
    def add(email: str, uuid: str = "", name: str = "", **kwargs) -> bool:
        try:
            state = NaiveProxyAdapter._state()
            if not state.get("installed"):
                _log("INFO", "naiveproxy.add: NaiveProxy not installed, skipping")
                return True
            username = _username_from_email(email)
            users = state.get("users", [])
            if any(u.get("username") == username for u in users):
                _log("INFO", f"naiveproxy.add: user {username!r} already exists, noop")
                return True
            try:
                from vless_installer.modules.proto_common import proto_gen_password
                password = proto_gen_password()
            except Exception:
                import secrets as _s
                password = _s.token_urlsafe(16)
            # Хэшируем пароль для Caddyfile
            try:
                from vless_installer.modules.naiveproxy import _hash_password
                password_hash = _hash_password(password)
            except Exception:
                password_hash = ""
            users.append({
                "username": username,
                "password": password,
                "password_hash": password_hash,
            })
            state["users"] = users
            NaiveProxyAdapter._save_state(state)
            return NaiveProxyAdapter._apply(state)
        except Exception as e:
            _log("ERROR", f"naiveproxy.add: exception for {email!r}: {e}")
            return False

    @staticmethod
    def remove(email: str, **kwargs) -> bool:
        try:
            state = NaiveProxyAdapter._state()
            if not state.get("installed"):
                return True
            username = _username_from_email(email)
            users = state.get("users", [])
            new_users = [u for u in users if u.get("username") != username]
            if len(new_users) == len(users):
                _log("INFO", f"naiveproxy.remove: user {username!r} not found, noop")
                return True
            state["users"] = new_users
            NaiveProxyAdapter._save_state(state)
            return NaiveProxyAdapter._apply(state)
        except Exception as e:
            _log("ERROR", f"naiveproxy.remove: exception for {email!r}: {e}")
            return False

    @staticmethod
    def block(email: str, reason: str = "manual", **kwargs) -> bool:
        _log("INFO", f"naiveproxy.block: removing user for {email!r} (reason={reason})")
        return NaiveProxyAdapter.remove(email)

    @staticmethod
    def unblock(email: str, **kwargs) -> bool:
        _log("INFO", f"naiveproxy.unblock: re-creating user for {email!r} (new password)")
        return NaiveProxyAdapter.add(email)


class MtprotoAdapter:
    """Adapter для MTProto/Telemt. TOML config в /etc/telemt/telemt.toml."""

    PROTOCOL_NAME = "mtproto"

    @staticmethod
    def _load_users() -> dict:
        try:
            from vless_installer.modules.mtproto import _load_users
            return _load_users()
        except Exception:
            return {}

    @staticmethod
    def _save_users(users: dict) -> None:
        try:
            from vless_installer.modules.mtproto import _save_users
            _save_users(users)
            # _save_users в mtproto.py уже рестартит telemt
        except Exception as e:
            _log("ERROR", f"mtproto._save_users: {e}")

    @staticmethod
    def add(email: str, uuid: str = "", name: str = "", **kwargs) -> bool:
        try:
            if not _TELEMT_TOML_FILE.exists():
                _log("INFO", "mtproto.add: Telemt not installed, skipping")
                return True
            users = MtprotoAdapter._load_users()
            username = _username_from_email(email)
            if username in users:
                _log("INFO", f"mtproto.add: user {username!r} already exists, noop")
                return True
            try:
                from vless_installer.modules.mtproto import _generate_secret
                secret = _generate_secret()
            except Exception:
                import secrets as _s
                secret = _s.token_hex(16)
            users[username] = secret
            MtprotoAdapter._save_users(users)
            return True
        except Exception as e:
            _log("ERROR", f"mtproto.add: exception for {email!r}: {e}")
            return False

    @staticmethod
    def remove(email: str, **kwargs) -> bool:
        try:
            if not _TELEMT_TOML_FILE.exists():
                return True
            users = MtprotoAdapter._load_users()
            username = _username_from_email(email)
            if username not in users:
                _log("INFO", f"mtproto.remove: user {username!r} not found, noop")
                return True
            # Telemt отказывается удалять последнего пользователя
            if len(users) <= 1:
                _log("WARN", f"mtproto.remove: cannot remove last user {username!r}")
                return True
            del users[username]
            MtprotoAdapter._save_users(users)
            return True
        except Exception as e:
            _log("ERROR", f"mtproto.remove: exception for {email!r}: {e}")
            return False

    @staticmethod
    def block(email: str, reason: str = "manual", **kwargs) -> bool:
        _log("INFO", f"mtproto.block: removing user for {email!r} (reason={reason})")
        return MtprotoAdapter.remove(email)

    @staticmethod
    def unblock(email: str, **kwargs) -> bool:
        _log("INFO", f"mtproto.unblock: re-creating user for {email!r} (new secret)")
        return MtprotoAdapter.add(email)


class FptnAdapter:
    """Adapter для FPTN. users.list hot-reloaded, без restart."""

    PROTOCOL_NAME = "fptn"

    @staticmethod
    def _state() -> dict:
        return _read_json(_FPTN_STATE_FILE)

    @staticmethod
    def _save_state(state: dict) -> None:
        _FPTN_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _FPTN_STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        try:
            _FPTN_STATE_FILE.chmod(0o600)
        except Exception:
            pass

    @staticmethod
    def add(email: str, uuid: str = "", name: str = "", bandwidth: int = 10000, **kwargs) -> bool:
        try:
            state = FptnAdapter._state()
            if not state.get("installed"):
                _log("INFO", "fptn.add: FPTN not installed, skipping")
                return True
            username = _username_from_email(email)
            # Проверяем что пользователя ещё нет в users.list
            try:
                from vless_installer.modules.fptn import _passwd_list_usernames, _passwd_add_user, _save_user_to_state
                existing = _passwd_list_usernames()
            except Exception:
                existing = []
                _save_user_to_state = None
                _passwd_add_user = None
            if username in existing:
                _log("INFO", f"fptn.add: user {username!r} already exists, noop")
                return True
            try:
                from vless_installer.modules.proto_common import proto_gen_password
                password = proto_gen_password()
            except Exception:
                import secrets as _s
                password = _s.token_urlsafe(16)
            ok, msg = _passwd_add_user(username, password, bandwidth)
            if not ok:
                _log("ERROR", f"fptn.add: _passwd_add_user failed for {username!r}: {msg}")
                return False
            # Сохраняем в state для subscription
            try:
                from vless_installer.modules.fptn import _save_user_to_state
                _save_user_to_state(username, password, bandwidth)
            except Exception as e:
                _log("WARN", f"fptn.add: cannot save to state: {e}")
            return True
        except Exception as e:
            _log("ERROR", f"fptn.add: exception for {email!r}: {e}")
            return False

    @staticmethod
    def remove(email: str, **kwargs) -> bool:
        try:
            state = FptnAdapter._state()
            if not state.get("installed"):
                return True
            username = _username_from_email(email)
            try:
                from vless_installer.modules.fptn import _passwd_list_usernames, _passwd_del_user, _remove_user_from_state
                existing = _passwd_list_usernames()
            except Exception:
                return True
            if username not in existing:
                _log("INFO", f"fptn.remove: user {username!r} not found, noop")
                return True
            if len(existing) <= 1:
                _log("WARN", f"fptn.remove: cannot remove last user {username!r}")
                return True
            ok = _passwd_del_user(username)
            if not ok:
                _log("ERROR", f"fptn.remove: _passwd_del_user failed for {username!r}")
                return False
            try:
                _remove_user_from_state(username)
            except Exception as e:
                _log("WARN", f"fptn.remove: cannot remove from state: {e}")
            return True
        except Exception as e:
            _log("ERROR", f"fptn.remove: exception for {email!r}: {e}")
            return False

    @staticmethod
    def block(email: str, reason: str = "manual", **kwargs) -> bool:
        _log("INFO", f"fptn.block: removing user for {email!r} (reason={reason})")
        return FptnAdapter.remove(email)

    @staticmethod
    def unblock(email: str, **kwargs) -> bool:
        _log("INFO", f"fptn.unblock: re-creating user for {email!r} (new password)")
        return FptnAdapter.add(email)


class Hysteria2Adapter:
    """Adapter для Hysteria2 — заглушка (общий пароль, нет per-user модели)."""

    PROTOCOL_NAME = "hysteria2"

    @staticmethod
    def add(email: str, uuid: str = "", name: str = "", **kwargs) -> bool:
        # Hysteria2 использует общий пароль на exit-ноду — per-user операции
        # не имеют смысла. Возвращаем True (no-op).
        state = _read_json(_STATE_FILE)
        h2 = state.get("hysteria2", {})
        if not h2.get("enabled"):
            _log("INFO", "hysteria2.add: Hysteria2 not enabled, skipping")
            return True
        _log("INFO", f"hysteria2.add: no per-user model for {email!r} (shared password), noop")
        return True

    @staticmethod
    def remove(email: str, **kwargs) -> bool:
        return True  # no-op

    @staticmethod
    def block(email: str, reason: str = "manual", **kwargs) -> bool:
        return True  # no-op

    @staticmethod
    def unblock(email: str, **kwargs) -> bool:
        return True  # no-op


# Реестр adapter'ов
PROTOCOL_ADAPTERS: Dict[str, type] = {
    "vless":      VlessAdapter,
    "awg":        AwgAdapter,
    "singbox":    SingboxAdapter,
    "mieru":      MieruAdapter,
    "mtproto":    MtprotoAdapter,
    "naiveproxy": NaiveProxyAdapter,
    "fptn":       FptnAdapter,
    "hysteria2":  Hysteria2Adapter,
}


# =============================================================================
#  TRANSACTIONAL COORDINATOR
# =============================================================================
def _state_files_for_protocols(protocols: List[str]) -> List[Path]:
    """Возвращает список state-файлов, которые затронуты операциями над
    указанными протоколами. Используется для snapshot/restore.
    """
    files = [_USERS_FILE, _XRAY_CONFIG_FILE]  # vless всегда
    if "awg" in protocols:
        files.append(_AWG_STATE_FILE)
    if "singbox" in protocols:
        files.append(_SINGBOX_STATE_FILE)
    if "mieru" in protocols:
        files.append(_MIERU_STATE_FILE)
    if "naiveproxy" in protocols:
        files.append(_NAIVE_STATE_FILE)
    if "fptn" in protocols:
        files.append(_FPTN_STATE_FILE)
        files.append(_FPTN_USERS_LIST)
    if "mtproto" in protocols:
        files.append(_TELEMT_TOML_FILE)
    if "vless" in protocols:
        files.extend([_TTL_FILE, _LIMITS_FILE, _BLOCKED_FILE])
    # Дедупликация
    seen = set()
    out = []
    for f in files:
        try:
            key = str(f.resolve())
        except Exception:
            key = str(f)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _run_protocol_op(adapter_class: type, op_name: str,
                     email: str, **kwargs) -> Tuple[bool, str]:
    """Вызывает op_name на adapter_class с обработкой ошибок.
    Возвращает (success, error_message).
    """
    try:
        method = getattr(adapter_class, op_name)
        ok = method(email=email, **kwargs)
        if ok:
            return True, ""
        return False, f"{adapter_class.PROTOCOL_NAME}.{op_name} returned False"
    except Exception as e:
        return False, f"{adapter_class.PROTOCOL_NAME}.{op_name} raised: {e}"


def add_user(email: str,
             protocols: Union[str, List[str]] = "all",
             ttl: Optional[int] = None,
             traffic_limit: Optional[int] = None,
             name: Optional[str] = None,
             uuid_str: Optional[str] = None) -> dict:
    """
    Добавляет пользователя across все указанные протоколы.

    Аргументы:
      email          — email пользователя (canonical identifier)
      protocols      — "all" или список протоколов
      ttl            — TTL в днях (None = без TTL)
      traffic_limit  — лимит трафика в GiB (None = без лимита)
      name           — отображаемое имя (None = часть до @ в email)
      uuid_str       — UUID (если None — генерируется новый)

    Возвращает dict:
      {"success": bool, "applied": [str], "failed": [str], "errors": [str]}

    Транзакционность:
      Если хотя бы один протокол упал — откатывает ВСЕ изменения
      (snapshot/restore pattern).
    """
    protocols_list = _normalize_protocols(protocols)
    result = {"success": False, "applied": [], "failed": [], "errors": []}

    if not email:
        result["errors"].append("email is required")
        return result

    # Генерируем UUID если не передан
    if not uuid_str:
        try:
            import uuid as _uuid
            uuid_str = str(_uuid.uuid4())
        except Exception as e:
            result["errors"].append(f"cannot generate uuid: {e}")
            return result

    # Идемпотентность: проверяем что пользователя ещё нет в VLESS
    existing = find_user_by_email(email)
    if existing:
        if existing.get("uuid") == uuid_str:
            _log("INFO", f"add_user: {email!r} already exists with same uuid, updating only protocols")
            # Продолжаем — для остальных протоколов это будет noop
        else:
            msg = f"user {email!r} already exists with different uuid"
            _log("ERROR", msg)
            result["errors"].append(msg)
            return result

    # Snapshot state-файлов для возможного отката
    snap = StateSnapshot()
    snap.capture(_state_files_for_protocols(protocols_list))

    name = name or _username_from_email(email)

    try:
        # 1) VLESS сначала — это source of truth
        if "vless" in protocols_list:
            ok, err = _run_protocol_op(VlessAdapter, "add", email,
                                       uuid=uuid_str, name=name)
            if ok:
                result["applied"].append("vless")
            else:
                result["failed"].append("vless")
                result["errors"].append(err)
                raise RuntimeError(err)

        # 2) Остальные протоколы
        for proto in protocols_list:
            if proto == "vless":
                continue
            adapter = PROTOCOL_ADAPTERS.get(proto)
            if not adapter:
                result["failed"].append(proto)
                result["errors"].append(f"unknown protocol: {proto}")
                continue
            ok, err = _run_protocol_op(adapter, "add", email,
                                       uuid=uuid_str, name=name)
            if ok:
                result["applied"].append(proto)
            else:
                result["failed"].append(proto)
                result["errors"].append(err)
                raise RuntimeError(err)

        # 3) TTL и traffic_limit (только если VLESS задействован)
        if "vless" in protocols_list:
            if ttl is not None:
                _set_ttl(email, ttl)
                result["applied"].append("ttl")
            if traffic_limit is not None:
                _set_traffic_limit(email, traffic_limit)
                result["applied"].append("traffic_limit")

        snap.commit()
        result["success"] = True
        _log_op("add", email, result["applied"], True,
                f"uuid={uuid_str}, ttl={ttl}, limit={traffic_limit}")
        return result

    except Exception as e:
        snap.restore()
        result["success"] = False
        _log_op("add", email, result["applied"] + result["failed"], False, str(e))
        return result


def remove_user(email: str,
                protocols: Union[str, List[str]] = "all") -> dict:
    """
    Удаляет пользователя across все указанные протоколы.
    Возвращает dict с результатами.
    """
    protocols_list = _normalize_protocols(protocols)
    result = {"success": False, "applied": [], "failed": [], "errors": []}

    if not email:
        result["errors"].append("email is required")
        return result

    # Snapshot
    snap = StateSnapshot()
    snap.capture(_state_files_for_protocols(protocols_list))

    try:
        # VLESS сначала (получаем UUID для sing-box)
        user = find_user_by_email(email)
        uuid_str = user.get("uuid", "") if user else ""

        if "vless" in protocols_list:
            ok, err = _run_protocol_op(VlessAdapter, "remove", email)
            if ok:
                result["applied"].append("vless")
            else:
                result["failed"].append("vless")
                result["errors"].append(err)
                raise RuntimeError(err)

        for proto in protocols_list:
            if proto == "vless":
                continue
            adapter = PROTOCOL_ADAPTERS.get(proto)
            if not adapter:
                continue
            ok, err = _run_protocol_op(adapter, "remove", email, uuid=uuid_str)
            if ok:
                result["applied"].append(proto)
            else:
                result["failed"].append(proto)
                result["errors"].append(err)
                raise RuntimeError(err)

        # Удаляем TTL и traffic_limit (если VLESS удалён)
        if "vless" in protocols_list:
            _remove_ttl(email)
            _remove_traffic_limit(email)

        snap.commit()
        result["success"] = True
        _log_op("remove", email, result["applied"], True)
        return result

    except Exception as e:
        snap.restore()
        result["success"] = False
        _log_op("remove", email, result["applied"] + result["failed"], False, str(e))
        return result


def block_user(email: str,
               reason: str = "manual",
               protocols: Union[str, List[str]] = "all") -> dict:
    """
    Блокирует пользователя across все указанные протоколы.
    Для VLESS: ставит blocked=True, удаляет из xray config (entry сохраняется).
    Для остальных: remove (пересоздаётся при unblock).
    """
    protocols_list = _normalize_protocols(protocols)
    result = {"success": False, "applied": [], "failed": [], "errors": []}

    if not email:
        result["errors"].append("email is required")
        return result

    snap = StateSnapshot()
    snap.capture(_state_files_for_protocols(protocols_list))

    try:
        user = find_user_by_email(email)
        uuid_str = user.get("uuid", "") if user else ""

        if "vless" in protocols_list:
            ok, err = _run_protocol_op(VlessAdapter, "block", email, reason=reason)
            if ok:
                result["applied"].append("vless")
            else:
                result["failed"].append("vless")
                result["errors"].append(err)
                raise RuntimeError(err)

        for proto in protocols_list:
            if proto == "vless":
                continue
            adapter = PROTOCOL_ADAPTERS.get(proto)
            if not adapter:
                continue
            ok, err = _run_protocol_op(adapter, "block", email,
                                       reason=reason, uuid=uuid_str)
            if ok:
                result["applied"].append(proto)
            else:
                result["failed"].append(proto)
                result["errors"].append(err)
                raise RuntimeError(err)

        snap.commit()
        result["success"] = True
        _log_op("block", email, result["applied"], True, f"reason={reason}")
        return result

    except Exception as e:
        snap.restore()
        result["success"] = False
        _log_op("block", email, result["applied"] + result["failed"], False, str(e))
        return result


def unblock_user(email: str,
                 protocols: Union[str, List[str]] = "all") -> dict:
    """
    Снимает блокировку across все указанные протоколы.
    Для VLESS: снимает blocked=True, возвращает в xray config.
    Для остальных: пересоздаёт аккаунт (с НОВЫМИ кредами — старые потеряны).
    """
    protocols_list = _normalize_protocols(protocols)
    result = {"success": False, "applied": [], "failed": [], "errors": []}

    if not email:
        result["errors"].append("email is required")
        return result

    snap = StateSnapshot()
    snap.capture(_state_files_for_protocols(protocols_list))

    try:
        user = find_user_by_email(email)
        uuid_str = user.get("uuid", "") if user else ""

        if "vless" in protocols_list:
            ok, err = _run_protocol_op(VlessAdapter, "unblock", email)
            if ok:
                result["applied"].append("vless")
            else:
                result["failed"].append("vless")
                result["errors"].append(err)
                raise RuntimeError(err)

        for proto in protocols_list:
            if proto == "vless":
                continue
            adapter = PROTOCOL_ADAPTERS.get(proto)
            if not adapter:
                continue
            ok, err = _run_protocol_op(adapter, "unblock", email, uuid=uuid_str)
            if ok:
                result["applied"].append(proto)
            else:
                result["failed"].append(proto)
                result["errors"].append(err)
                raise RuntimeError(err)

        snap.commit()
        result["success"] = True
        _log_op("unblock", email, result["applied"], True)
        return result

    except Exception as e:
        snap.restore()
        result["success"] = False
        _log_op("unblock", email, result["applied"] + result["failed"], False, str(e))
        return result


def update_limits(email: str,
                  ttl: Optional[int] = None,
                  traffic_limit: Optional[int] = None,
                  protocols: Union[str, List[str]] = "all") -> dict:
    """
    Обновляет TTL и/или лимит трафика для пользователя.
    TTL: int дней (None = не менять, 0 = снять).
    traffic_limit: int GiB (None = не менять, 0 = снять).
    """
    result = {"success": False, "applied": [], "failed": [], "errors": []}

    if not email:
        result["errors"].append("email is required")
        return result

    try:
        if ttl is not None:
            if ttl > 0:
                _set_ttl(email, ttl)
                result["applied"].append(f"ttl={ttl}d")
            elif ttl == 0:
                _remove_ttl(email)
                result["applied"].append("ttl=removed")
        if traffic_limit is not None:
            if traffic_limit > 0:
                _set_traffic_limit(email, traffic_limit)
                result["applied"].append(f"limit={traffic_limit}GiB")
            elif traffic_limit == 0:
                _remove_traffic_limit(email)
                result["applied"].append("limit=removed")
        result["success"] = True
        _log_op("update_limits", email, [], True, ", ".join(result["applied"]))
        return result
    except Exception as e:
        result["errors"].append(str(e))
        _log_op("update_limits", email, [], False, str(e))
        return result


# =============================================================================
#  TTL / TRAFFIC LIMIT helpers (тонкие обёртки над существующими модулями)
# =============================================================================
def _set_ttl(email: str, days: int) -> None:
    """Устанавливает TTL через существующий ttl_users._ttl_set."""
    try:
        from vless_installer.modules.ttl_users import _ttl_set
        _ttl_set(email, days)
    except Exception as e:
        _log("ERROR", f"_set_ttl: {e}")
        raise


def _remove_ttl(email: str) -> None:
    try:
        from vless_installer.modules.ttl_users import _ttl_remove
        _ttl_remove(email)
    except Exception as e:
        _log("ERROR", f"_remove_ttl: {e}")
        raise


def _set_traffic_limit(email: str, limit_gib: int) -> None:
    """Устанавливает лимит трафика в traffic_limits.json."""
    try:
        from vless_installer.modules.traffic_tracking import _limits_load, _limits_save
        limits = _limits_load()
        limits[email] = {
            "limit_gb":    limit_gib,
            "used_bytes":  0,
            "disabled":    False,
            "disabled_at": "",
        }
        _limits_save(limits)
    except Exception as e:
        _log("ERROR", f"_set_traffic_limit: {e}")
        raise


def _remove_traffic_limit(email: str) -> None:
    try:
        from vless_installer.modules.traffic_tracking import _limits_load, _limits_save
        limits = _limits_load()
        if email in limits:
            del limits[email]
            _limits_save(limits)
    except Exception as e:
        _log("ERROR", f"_remove_traffic_limit: {e}")
        raise


# =============================================================================
#  CRON ENTRYPOINTS (обратная совместимость)
# =============================================================================
def check_ttl_expired() -> int:
    """
    Единый cron-entrypoint: проверяет всех пользователей с TTL, блокирует
    истёкших across все протоколы, шлёт 24h-предупреждения.
    Возвращает количество заблокированных пользователей.

    Заменяет _ttl_check_and_expire() из ttl_users.py (которая теперь делегирует сюда).
    """
    _log("INFO", "check_ttl_expired: starting")
    blocked_count = 0
    try:
        from vless_installer.modules.ttl_users import (
            _ttl_load, _ttl_is_expired, _ttl_expires_within_hours,
        )
        ttl_db = _ttl_load()
        for email, info in ttl_db.items():
            if not isinstance(info, dict):
                continue
            expires_at = info.get("expires_at", "")
            if not expires_at:
                continue
            # 24h-предупреждение
            if not info.get("notified_24h") and _ttl_expires_within_hours(expires_at, 24):
                try:
                    core = _core_module()
                    if hasattr(core, "_tg_notify_event"):
                        core._tg_notify_event("ttl_expiring",
                            f"Пользователь <b>{email}</b> истекает через 24ч")
                    info["notified_24h"] = True
                except Exception:
                    pass
            # Истёк — блокируем across все протоколы
            if _ttl_is_expired(expires_at):
                _log("INFO", f"check_ttl_expired: blocking {email!r} (TTL expired)")
                result = block_user(email, reason="ttl_expired")
                if result["success"]:
                    blocked_count += 1
                    try:
                        core = _core_module()
                        if hasattr(core, "_tg_notify_event"):
                            core._tg_notify_event("ttl_expired",
                                f"Пользователь <b>{email}</b> заблокирован (TTL истёк)")
                    except Exception:
                        pass
                else:
                    _log("ERROR", f"check_ttl_expired: failed to block {email!r}: {result['errors']}")
        # Сохраняем обновлённые notified_24h флаги
        try:
            from vless_installer.modules.ttl_users import _ttl_save
            _ttl_save(ttl_db)
        except Exception:
            pass
    except Exception as e:
        _log("ERROR", f"check_ttl_expired: {e}")
    _log("INFO", f"check_ttl_expired: done, blocked {blocked_count} users")
    return blocked_count


def check_traffic_limits() -> int:
    """
    Единый cron-entrypoint: проверяет лимиты трафика, блокирует превысивших
    across все протоколы.
    Возвращает количество заблокированных.

    ЗАМЕЧАНИЕ: в отличие от старого _check_traffic_limits_once() который УДАЛЯЛ
    пользователя, эта функция БЛОКИРУЕТ его (block_user) — это менее деструктивно
    и позволяет разблокировать через unblock_user().
    """
    _log("INFO", "check_traffic_limits: starting")
    blocked_count = 0
    try:
        from vless_installer.modules.traffic_tracking import (
            _limits_load, _limits_save, _query_user_traffic_bytes,
            _stats_api_is_configured,
        )
        if not _stats_api_is_configured():
            _log("WARN", "check_traffic_limits: Stats API not configured, skipping")
            return 0
        limits = _limits_load()
        for email, cfg in limits.items():
            if not isinstance(cfg, dict):
                continue
            limit_gb = cfg.get("limit_gb", 0)
            if not limit_gb or cfg.get("disabled"):
                continue
            used_bytes = _query_user_traffic_bytes(email)
            cfg["used_bytes"] = used_bytes
            limit_bytes = limit_gb * 1024**3
            if used_bytes >= limit_bytes:
                _log("INFO", f"check_traffic_limits: blocking {email!r} "
                    f"({used_bytes/1024**3:.2f} GiB / {limit_gb} GiB)")
                result = block_user(email, reason="traffic_limit")
                if result["success"]:
                    blocked_count += 1
                    cfg["disabled"] = True
                    cfg["disabled_at"] = datetime.now(timezone.utc).isoformat()
                    try:
                        core = _core_module()
                        if hasattr(core, "_tg_notify_event"):
                            core._tg_notify_event("traffic_limit",
                                f"Пользователь <b>{email}</b> заблокирован: "
                                f"использовано {used_bytes/1024**3:.2f} GiB из {limit_gb} GiB")
                    except Exception:
                        pass
                else:
                    _log("ERROR", f"check_traffic_limits: failed to block {email!r}: {result['errors']}")
        _limits_save(limits)
    except Exception as e:
        _log("ERROR", f"check_traffic_limits: {e}")
    _log("INFO", f"check_traffic_limits: done, blocked {blocked_count} users")
    return blocked_count


def run_cleanup() -> dict:
    """
    Единый cron-entrypoint, заменяющий несколько разрозненных:
      1. check_ttl_expired()       (был --ttl-check)
      2. check_traffic_limits()    (был inline в xray-traffic-limits.sh)
      3. awgs_expires_check()      (был отдельный cron для AWG)
    Возвращает dict с количеством заблокированных/удалённых.
    """
    _log("INFO", "run_cleanup: starting")
    result = {
        "ttl_blocked":       0,
        "traffic_blocked":   0,
        "awg_peers_removed": 0,
    }
    try:
        result["ttl_blocked"] = check_ttl_expired()
    except Exception as e:
        _log("ERROR", f"run_cleanup: check_ttl_expired failed: {e}")
    try:
        result["traffic_blocked"] = check_traffic_limits()
    except Exception as e:
        _log("ERROR", f"run_cleanup: check_traffic_limits failed: {e}")
    try:
        # AWG peer expiry — делегируем в существующую функцию
        from vless_installer.modules.awg_expires import awgs_expires_check
        result["awg_peers_removed"] = awgs_expires_check() or 0
    except Exception as e:
        _log("WARN", f"run_cleanup: awgs_expires_check failed (AWG not installed?): {e}")
    _log("INFO", f"run_cleanup: done: {result}")
    return result


# =============================================================================
#  Публичный экспорт
# =============================================================================
__all__ = [
    # Coordinator API
    "add_user",
    "remove_user",
    "block_user",
    "unblock_user",
    "update_limits",
    # Cron entrypoints
    "check_ttl_expired",
    "check_traffic_limits",
    "run_cleanup",
    # Identity helpers
    "find_user_by_email",
    "find_user_by_uuid",
    "resolve_user",
    # Protocol adapters (для тестов и расширений)
    "VlessAdapter",
    "AwgAdapter",
    "SingboxAdapter",
    "MieruAdapter",
    "NaiveProxyAdapter",
    "MtprotoAdapter",
    "FptnAdapter",
    "Hysteria2Adapter",
    "PROTOCOL_ADAPTERS",
    "ALL_PROTOCOLS",
    # Snapshot/restore
    "StateSnapshot",
    # Constants
    "_USERS_FILE",
    "_TTL_FILE",
    "_LIMITS_FILE",
    "_BLOCKED_FILE",
    "_AWG_STATE_FILE",
    "_SINGBOX_STATE_FILE",
    "_MIERU_STATE_FILE",
    "_NAIVE_STATE_FILE",
    "_FPTN_STATE_FILE",
    "_TELEMT_TOML_FILE",
    "_FPTN_USERS_LIST",
    "_LOG_FILE",
]
