"""
chimera/modules/hysteria2_sync.py
───────────────────────────────────────────────────────────────────────────────
Sync contract bridge для Hysteria2 (v4.25).

Hysteria2 — shared-password модель (НЕ per-user):
  • Один auth password на всех клиентов.
  • Нет per-user billing/identity — трафик агрегированный.
  • Пароль хранится в state["hysteria2"]["auth_password"] + obfs salamander password.

Поэтому sync contract здесь — это NO-OP:
  • is_active() — True если Hysteria2 установлена и сервис запущен.
  • ensure_user_full(user) — возвращает True (no-op). Hysteria2 не требует
    per-user аккаунта — все юзеры используют тот же auth password.
  • remove_user_full(user) — возвращает True (no-op).
  • rename_user_full — возвращает True (no-op).

Зачем тогда нужен этот модуль в реестре _SYNCABLE_PROTOCOLS?
  • Чтобы подписка/web-панель/user portal знали, что Hysteria2 активна.
  • Чтобы при установке Hysteria2 все существующие VLESS-юзеры автоматически
    получили hysteria2:// ссылку в подписке (через _SUBSCRIBABLE_PROTOCOLS
    в subscription.py).
  • Dispatcher не делает никаких per-user операций — просто подтверждает
    что Hysteria2 "синхронизирована" (= активна для всех).

Если в будущем появится per-user auth для Hysteria2 (obfs per-user password),
контракт можно расширить — логика инкапсулирована здесь.
"""
from __future__ import annotations


def is_active() -> bool:
    """True если Hysteria2 transport включена в state.json.

    Hysteria2 — это транспорт каскада (не отдельный inbound). "Активна"
    значит state["hysteria2"]["enabled"] == True ИЛИ
    state["hysteria2"]["transport_only"] == True.
    """
    try:
        from chimera.modules.hysteria2_common import _load_h2_state
        h2 = _load_h2_state()
        if not h2:
            return False
        # enabled = full Hysteria2 (server + transport)
        # transport_only = только как транспорт каскада (без standalone server)
        return bool(h2.get("enabled") or h2.get("transport_only"))
    except Exception:
        return False


def ensure_user_full(user: dict) -> bool:
    """NO-OP — Hysteria2 использует shared password, не per-user аккаунты.
    Возвращает True чтобы dispatcher считал операцию успешной."""
    return True


def ensure_user(name: str) -> bool:
    """Legacy contract — NO-OP."""
    return True


def remove_user_full(user: dict) -> bool:
    """NO-OP — Hysteria2 использует shared password."""
    return True


def remove_user(name: str) -> bool:
    """Legacy contract — NO-OP."""
    return True


def rename_user_full(old_user: dict, new_user: dict) -> bool:
    """NO-OP — Hysteria2 использует shared password."""
    return True


def rename_user(old_name: str, new_name: str) -> bool:
    """Legacy contract — NO-OP."""
    return True
