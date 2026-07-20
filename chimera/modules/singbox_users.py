"""
chimera/modules/singbox_users.py
───────────────────────────────────────────────────────────────────────────────
Bridge между sing-box inbound'ами и unified users (_unified_load_users /
_unified_save_users из users_manager.py).

Идея:
  • UUID для TUIC — берётся из существующего списка unified users
  • Пароль для ShadowTLS/AnyTLS/Trojan — генерируется и хранится В singbox_state
    (потому что unified users не имеют поля "password" — у них только UUID).
    UUID привязывает sing-box-аккаунт к VLESS-юзеру.

  При добавлении нового пользователя в unified (через меню Xray):
    1. _unified_save_users() сохраняет его в users.json
    2. singbox_sync_users() вызывается вручную или автоматически — добавляет
       соответствующие записи в inbounds.{shadowtls,anytls,tuic,trojan}.users

  При удалении пользователя:
    1. _unified_save_users() удаляет его
    2. singbox_sync_users() убирает его из всех sing-box inbound'ов

Функции:
  • singbox_sync_users()       — синхронизация sing-box users с unified
  • singbox_get_users()        — возвращает список unified users
  • singbox_gen_password()     — генерирует пароль для ShadowTLS/AnyTLS/Trojan
  • singbox_gen_tuic_password() — пароль для TUIC (отдельный, длиннее)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import secrets
from typing import Optional

from chimera.modules.singbox_common import (
    info, success, warn, error, log_to_file,
)
from chimera.modules.singbox_state import (
    singbox_state_load, singbox_state_save, singbox_state_get_inbound,
    singbox_state_update_inbound, singbox_state_get_enabled_protocols,
)


# ============================================================================
#  Генерация паролей
# ============================================================================
def singbox_gen_password(length: int = 22, padded: bool = False) -> str:
    """Генерирует пароль для ShadowTLS/AnyTLS/Trojan (base64-urlsafe, 22 символа).

    Пароль — это просто plaintext string, sing-box сравнивает строки напрямую
    (см. официальную доку sing-box: 'password: string (required) — User password').

    v4.23.21 (ОТКАЧЕНО в v4.23.23): я добавил padded=True с '==' думая, что
    AnyTLS требует валидный base64. Это было неверное предположение — AnyTLS
    использует пароль как plaintext, не base64-decoded bytes. С `==` или без —
    не важно, главное чтобы строки совпадали на клиенте и сервере.

    padded=False по умолчанию (как было изначально) — 22 символа без '=='.
    Параметр padded оставлен для тестов.
    """
    import base64
    raw = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode()
    if not padded:
        return raw.rstrip("=")
    return raw  # с паддингом '==' (если когда-то понадобится)


def singbox_gen_tuic_password(length: int = 22) -> str:
    """Пароль для TUIC v5 — тот же формат, отдельная генерация для логической изоляции."""
    return singbox_gen_password(length)


# ============================================================================
#  Bridge к unified users
# ============================================================================
def _unified_load_users() -> list[dict]:
    """Ленивый импорт _unified_load_users из users_manager.py."""
    try:
        from chimera.modules.users_manager import _unified_load_users
        return _unified_load_users()
    except Exception as e:
        warn(f"Не удалось загрузить unified users: {e}")
        return []


def singbox_get_users() -> list[dict]:
    """Возвращает список unified users (UUID/email/name/disabled)."""
    return [u for u in _unified_load_users() if not u.get("disabled")]


def singbox_get_user_by_uuid(uuid: str) -> Optional[dict]:
    for u in singbox_get_users():
        if u.get("uuid") == uuid:
            return u
    return None


# ============================================================================
#  Синхронизация
# ============================================================================
def singbox_sync_users() -> dict:
    """
    Синхронизирует пользователей sing-box с unified users.

    Алгоритм:
      1. Грузим unified users (активные, без disabled)
      2. Грузим sing-box state
      3. Для каждого включённого inbound'а:
         - UUID-ы пользователей в sing-box должны совпадать с unified UUIDs
         - Если в sing-box есть UUID, которого нет в unified — удаляем
         - Если в unified есть UUID, которого нет в sing-box — добавляем с новым паролем
      4. Сохраняем state

    Возвращает dict:
      {"added": int, "removed": int, "kept": int, "errors": [str]}
    """
    unified_users = singbox_get_users()
    unified_uuids = {u["uuid"] for u in unified_users}

    state = singbox_state_load()
    inbounds = state.get("inbounds", {})

    result = {"added": 0, "removed": 0, "kept": 0, "errors": []}

    # Протоколы, использующие users: shadowtls (password), trojan (password),
    # anytls (password), tuic (uuid+password).
    # Для всех протоколов схема одинаковая: user = {uuid, password, name?}

    for proto_name, proto_config in inbounds.items():
        if not proto_config.get("enabled"):
            continue

        existing_users = proto_config.get("users", [])
        existing_uuids = {u.get("uuid", "") for u in existing_users if u.get("uuid")}

        # Если у протокола нет users (например trojan внутренний без auth) — пропускаем
        if not existing_users and proto_name not in ("shadowtls", "anytls", "trojan", "tuic"):
            continue

        # Удаляем тех, кого нет в unified
        new_users = [u for u in existing_users if u.get("uuid") in unified_uuids]
        removed_count = len(existing_users) - len(new_users)

        # Добавляем тех, кто есть в unified, но нет в sing-box
        for u in unified_users:
            uuid = u["uuid"]
            if uuid not in existing_uuids:
                # Генерируем пароль (для TUIC — отдельный, для остальных — общий)
                if proto_name == "tuic":
                    password = singbox_gen_tuic_password()
                    new_users.append({
                        "uuid":     uuid,
                        "password": password,
                        "name":     u.get("name", u.get("email", uuid[:8])),
                    })
                else:
                    password = singbox_gen_password()
                    user_entry = {
                        "uuid":     uuid,
                        "password": password,
                        "name":     u.get("name", u.get("email", uuid[:8])),
                    }
                    new_users.append(user_entry)

        added_count = len(new_users) - (len(existing_users) - removed_count)
        kept_count = len(new_users) - added_count

        proto_config["users"] = new_users
        result["added"] += added_count
        result["removed"] += removed_count
        result["kept"] += kept_count

    state["inbounds"] = inbounds
    singbox_state_save(state)

    if result["added"] or result["removed"]:
        info(f"Синхронизация sing-box users: +{result['added']} добавлено, "
             f"-{result['removed']} удалено, ={result['kept']} оставлено")
    log_to_file("INFO", f"singbox_sync_users: {result}")
    return result


# ============================================================================
#  Управление пользователями sing-box
# ============================================================================
def singbox_state_add_user_to_all_protocols(uuid: str, name: str = "") -> bool:
    """Добавляет пользователя (UUID) во все включённые inbound'ы sing-box."""
    state = singbox_state_load()
    inbounds = state.get("inbounds", {})

    for proto_name, proto_config in inbounds.items():
        if not proto_config.get("enabled"):
            continue
        if proto_name not in ("shadowtls", "anytls", "trojan", "tuic"):
            continue

        users = proto_config.setdefault("users", [])
        # Проверка на дубликат
        if any(u.get("uuid") == uuid for u in users):
            continue

        if proto_name == "tuic":
            password = singbox_gen_tuic_password()
        else:
            password = singbox_gen_password()

        users.append({
            "uuid":     uuid,
            "password": password,
            "name":     name or uuid[:8],
        })

    singbox_state_save(state)
    return True


def singbox_state_remove_user_from_all_protocols(uuid: str) -> bool:
    """Удаляет пользователя (UUID) из всех inbound'ов sing-box."""
    state = singbox_state_load()
    inbounds = state.get("inbounds", {})

    for proto_name, proto_config in inbounds.items():
        users = proto_config.get("users", [])
        proto_config["users"] = [u for u in users if u.get("uuid") != uuid]

    state["inbounds"] = inbounds
    return singbox_state_save(state)


def singbox_state_list_users(protocol: str = "") -> list[dict]:
    """Возвращает список пользователей конкретного протокола
    (или всех включённых, если protocol="")."""
    state = singbox_state_load()
    inbounds = state.get("inbounds", {})
    result: list[dict] = []

    if protocol:
        ib = inbounds.get(protocol, {})
        if ib.get("enabled"):
            for u in ib.get("users", []):
                u_copy = dict(u)
                u_copy["protocol"] = protocol
                result.append(u_copy)
    else:
        for proto_name, ib in inbounds.items():
            if not ib.get("enabled"):
                continue
            for u in ib.get("users", []):
                u_copy = dict(u)
                u_copy["protocol"] = proto_name
                result.append(u_copy)

    return result


# ============================================================================
#  SYNC CONTRACT (v4.25) — для реестра _SYNCABLE_PROTOCOLS в rest_api.py
#
#  sing-box особенный:
#    • Identity = UUID (canonical VLESS UUID). НЕ email/name — у sing-box
#      внутренний users[] массив с {uuid, password, name} для каждого
#      включённого inbound'а (shadowtls/anytls/trojan/tuic).
#    • Пароль генерируется случайно (singbox_gen_password) — НЕ детерминирован.
#      При remove+add пароль меняется → клиентам нужно перевыдать ссылки.
#    • NO сервис-рестарт при add/remove — только state.json обновляется.
#      sing-box подхватывает изменения при следующем reload/restart через
#      singbox_generate_config + singbox_validate_config + systemctl reload.
#      Для интерактивных ops (TUI/REST) мы делаем это здесь. Cron-батч
#      идёт через user_lifecycle.batch_context().
#
#  Реестр вызывает:
#    is_active()           — sing-box сервис запущен
#    ensure_user_full(u)   — добавить UUID во все включённые inbounds
#    remove_user_full(u)   — удалить UUID из всех inbounds
#    rename_user_full(o,n) — update name field (UUID не меняется)
# ============================================================================
def is_active() -> bool:
    """True если sing-box установлен И сервис запущен."""
    try:
        from chimera.modules.singbox_common import _service_active
        # Проверяем что хотя бы один inbound включён.
        state = singbox_state_load()
        if not state.get("installed"):
            return False
        any_enabled = any(
            ib.get("enabled") for ib in state.get("inbounds", {}).values()
        )
        if not any_enabled:
            return False
        return _service_active()
    except Exception:
        return False


def ensure_user_full(user: dict) -> bool:
    """Добавляет UUID пользователя во все включённые sing-box inbounds.

    Требует uuid в user dict. Если уже есть во всех inbound'ах — no-op.
    Пароль генерируется случайно для каждого inbound'а. State обновляется,
    конфиг регенерируется, sing-box reload.
    """
    try:
        uuid_str = user.get("uuid", "") or ""
        if not uuid_str:
            return False
        # name = display name (для логов sing-box, не влияет на auth).
        name = user.get("name") or user.get("email") or user.get("device_label") or uuid_str[:8]
        # singbox_state_add_user_to_all_protocols идемпотентна (проверяет дубликат).
        ok = singbox_state_add_user_to_all_protocols(uuid_str, name)
        if not ok:
            return False
        # Регенерируем конфиг и reload.
        try:
            from chimera.modules.singbox_config import singbox_generate_config
            from chimera.modules.singbox_common import _systemctl
            singbox_generate_config()
            _systemctl("reload")
        except Exception:
            pass  # не критично — state сохранён, при следующем reload подхватит
        return True
    except Exception:
        return False


def ensure_user(name: str) -> bool:
    """Legacy contract — НЕ работает для sing-box без UUID.
    sing-box идентифицирует пользователей по UUID, не по name.

    Возвращает True (no-op) чтобы не ломать диспетчер. TUI/REST API
    должны передавать full user dict через ensure_user_full.
    """
    return True


def remove_user_full(user: dict) -> bool:
    """Удаляет UUID из всех sing-box inbounds."""
    try:
        uuid_str = user.get("uuid", "") or ""
        if not uuid_str:
            return False
        ok = singbox_state_remove_user_from_all_protocols(uuid_str)
        if not ok:
            return False
        try:
            from chimera.modules.singbox_config import singbox_generate_config
            from chimera.modules.singbox_common import _systemctl
            singbox_generate_config()
            _systemctl("reload")
        except Exception:
            pass
        return True
    except Exception:
        return False


def remove_user(name: str) -> bool:
    """Legacy contract — не работает без UUID. No-op."""
    return True


def rename_user_full(old_user: dict, new_user: dict) -> bool:
    """Rename = обновить name field во всех inbounds (UUID не меняется).

    sing-box users идентифицируются по UUID, поэтому rename не требует
    remove+add — просто обновляем поле name в существующих записях.
    Пароль НЕ меняется (в отличие от remove+add).
    """
    try:
        uuid_str = new_user.get("uuid") or old_user.get("uuid", "") or ""
        if not uuid_str:
            return False
        new_name = (new_user.get("name") or new_user.get("email")
                    or new_user.get("device_label") or uuid_str[:8])
        state = singbox_state_load()
        inbounds = state.get("inbounds", {})
        changed = False
        for proto_name, proto_config in inbounds.items():
            if not proto_config.get("enabled"):
                continue
            if proto_name not in ("shadowtls", "anytls", "trojan", "tuic"):
                continue
            users = proto_config.get("users", [])
            for u in users:
                if u.get("uuid") == uuid_str:
                    u["name"] = new_name
                    changed = True
        if changed:
            singbox_state_save(state)
            try:
                from chimera.modules.singbox_config import singbox_generate_config
                from chimera.modules.singbox_common import _systemctl
                singbox_generate_config()
                _systemctl("reload")
            except Exception:
                pass
        return True
    except Exception:
        return False


def rename_user(old_name: str, new_name: str) -> bool:
    """Legacy contract — не работает без UUID. No-op."""
    return True
