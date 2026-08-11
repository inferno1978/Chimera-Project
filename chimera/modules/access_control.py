"""
chimera/modules/access_control.py
───────────────────────────────────────────────────────────────────────────────
Общий модоль парольной защиты скрытых меню Chimera.

Поддерживает два типа паролей:
  1. Master-пароль (админ) — задаётся один раз, не протухает.
     Проверяется через PBKDF2-HMAC-SHA256 (600000 итераций, salt 16 байт).
  2. OTP (одноразовый для пользователя) — 8-символьный код, авто-генерируется
     после каждого использования. После успешного ввода — протухает,
     генерируется новый OTP.

Формат файла (JSON, chmod 0600):
  {
    "master": {
      "salt": "<hex>", "hash": "<hex>",
      "iterations": 600000, "algo": "pbkdf2_sha256"
    },
    "otp": {
      "current_code": "Ab3Km9Xz",
      "salt": "<hex>", "hash": "<hex>",
      "iterations": 600000, "algo": "pbkdf2_sha256",
      "used": false, "created_at": "2026-08-09T..."
    }
  }

Backward compatibility: старый формат (только salt/hash/iterations без
"master" ключа) → считается master-паролем. OTP автоматически создаётся
при первом вызове init_otp().

Публичный API:
  verify_access(hash_file: Path, password: str) -> AccessResult
  init_master(hash_file: Path, password: str) -> bool
  init_otp(hash_file: Path) -> str | None
  get_current_otp(hash_file: Path) -> str | None
  rotate_otp(hash_file: Path) -> str | None
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
import string
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_ITERATIONS = 600_000
_ALGO = "pbkdf2_sha256"
_OTP_LENGTH = 8
_OTP_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits


@dataclass
class AccessResult:
    """Результат проверки пароля."""
    granted: bool
    is_master: bool = False
    otp_rotated: bool = False
    new_otp: str = ""


def _compute_hash(password: str, salt: bytes, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    ).hex()


def _load_file(hash_file: Path) -> dict:
    """Загружает hash-файл. Возвращает {} если нет/повреждён."""
    try:
        if not hash_file.exists():
            return {}
        return json.loads(hash_file.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_file(hash_file: Path, data: dict) -> bool:
    """Сохраняет hash-файл (chmod 0600)."""
    try:
        hash_file.parent.mkdir(parents=True, exist_ok=True)
        hash_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        hash_file.chmod(0o600)
        return True
    except Exception:
        return False


def _verify_hash(password: str, stored: dict) -> bool:
    """Проверяет пароль против stored hash dict ({salt, hash, iterations, algo})."""
    if not password or not stored:
        return False
    try:
        if stored.get("algo") != _ALGO:
            return False
        salt = bytes.fromhex(stored["salt"])
        stored_hash = stored["hash"]
        iterations = int(stored.get("iterations", _ITERATIONS))
        computed = _compute_hash(password, salt, iterations)
        return hmac.compare_digest(computed, stored_hash)
    except Exception:
        return False


def _generate_otp_code() -> str:
    """Генерирует случайный OTP код (8 символов)."""
    return "".join(secrets.choice(_OTP_ALPHABET) for _ in range(_OTP_LENGTH))


def init_master(hash_file: Path, password: str) -> bool:
    """Устанавливает/меняет master-пароль.

    Сохраняет PBKDF2 hash в файл. НЕ перезаписывает существующий OTP.
    """
    if not password:
        return False
    data = _load_file(hash_file)
    salt = os.urandom(16)
    data["master"] = {
        "salt": salt.hex(),
        "hash": _compute_hash(password, salt, _ITERATIONS),
        "iterations": _ITERATIONS,
        "algo": _ALGO,
    }
    return _save_file(hash_file, data)


def init_otp(hash_file: Path) -> str | None:
    """Создаёт новый OTP если его нет или если предыдущий использован.

    Возвращает новый OTP код или None при ошибке.
    """
    data = _load_file(hash_file)
    # Если OTP уже есть и не использован — не генерируем новый.
    otp = data.get("otp")
    if otp and not otp.get("used", False):
        return otp.get("current_code", "")

    # Генерируем новый.
    code = _generate_otp_code()
    salt = os.urandom(16)
    data["otp"] = {
        "current_code": code,
        "salt": salt.hex(),
        "hash": _compute_hash(code, salt, _ITERATIONS),
        "iterations": _ITERATIONS,
        "algo": _ALGO,
        "used": False,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if not _save_file(hash_file, data):
        return None
    return code


def get_current_otp(hash_file: Path) -> str | None:
    """Возвращает текущий OTP код (если есть и не использован)."""
    data = _load_file(hash_file)
    otp = data.get("otp")
    if not otp or otp.get("used", True):
        return None
    return otp.get("current_code", "")


def rotate_otp(hash_file: Path) -> str | None:
    """Принудительно генерирует новый OTP (независимо от состояния старого).

    Возвращает новый OTP код или None при ошибке.
    """
    data = _load_file(hash_file)
    code = _generate_otp_code()
    salt = os.urandom(16)
    data["otp"] = {
        "current_code": code,
        "salt": salt.hex(),
        "hash": _compute_hash(code, salt, _ITERATIONS),
        "iterations": _ITERATIONS,
        "algo": _ALGO,
        "used": False,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if not _save_file(hash_file, data):
        return None
    return code


def verify_access(hash_file: Path, password: str) -> AccessResult:
    """Проверяет пароль против master и OTP.

    Логика:
      1. Проверка master → если совпал → доступ (OTP не трогается).
      2. Проверка OTP (если есть и не used) → если совпал →
         отметить used=True, сгенерировать новый OTP → доступ.
      3. Ни то ни другое → отказ.

    Backward compat: старый формат (salt/hash/iterations без "master")
    → считается master-паролем.
    """
    if not password:
        return AccessResult(granted=False)

    data = _load_file(hash_file)
    if not data:
        return AccessResult(granted=False)

    # 1. Проверка master.
    master_entry = data.get("master")
    if not master_entry:
        # Backward compat: старый формат — весь dict это master hash.
        if "salt" in data and "hash" in data and "iterations" in data:
            if _verify_hash(password, data):
                return AccessResult(granted=True, is_master=True)
    else:
        if _verify_hash(password, master_entry):
            return AccessResult(granted=True, is_master=True)

    # 2. Проверка OTP.
    otp_entry = data.get("otp")
    if otp_entry and not otp_entry.get("used", True):
        if _verify_hash(password, otp_entry):
            # OTP использован — ротация.
            new_code = rotate_otp(hash_file)
            return AccessResult(
                granted=True,
                is_master=False,
                otp_rotated=True,
                new_otp=new_code or "",
            )

    # 3. Отказ.
    return AccessResult(granted=False)


def unlock_menu(hash_file: Path, menu_title: str,
                box_top_fn=None, box_row_fn=None, box_sep_fn=None,
                box_bottom_fn=None, box_info_fn=None, box_warn_fn=None,
                cyan: str = "", nc: str = "", yellow: str = "",
                green: str = "", dim: str = "") -> bool:
    """Интерактивный ввод пароля (3 попытки, getpass без эха).

    Возвращает True если доступ разрешён, иначе False.
    Использует переданные функции для отрисовки UI.
    """
    if not hash_file.exists():
        return False

    for _attempt in range(3):
        os.system("clear")
        print()
        if box_top_fn:
            box_top_fn(menu_title)
            if box_row_fn:
                box_row_fn()
            if box_info_fn:
                box_info_fn("Доступ к этому разделу ограничен. Введите код доступа.")
            if box_row_fn:
                box_row_fn()
            if box_sep_fn:
                box_sep_fn()
            if box_warn_fn:
                box_warn_fn("Неверный код — раздел останется скрытым.")
            if box_bottom_fn:
                box_bottom_fn()
        else:
            print(f"=== {menu_title} ===")
            print("Доступ ограничен. Введите код доступа.")
        print()

        try:
            pwd = getpass.getpass(f"  {cyan}Код доступа:{nc} ")
        except (EOFError, KeyboardInterrupt):
            print()
            return False

        result = verify_access(hash_file, pwd)
        if result.granted:
            if result.otp_rotated and result.new_otp:
                # Показать админу новый OTP (если это был OTP вход).
                # Не показываем если master вход.
                print(f"\n  {green}Доступ разрешён.{nc}")
                print(f"  {dim}OTP использован. Новый OTP для следующего пользователя:{nc}")
                print(f"  {cyan}{result.new_otp}{nc}")
                print(f"  {dim}Сохраните его и передайте следующему пользователю.{nc}")
                time.sleep(3)
            return True

        print(f"\n  {yellow}Неверный код доступа.{nc}")
        time.sleep(2)

    return False
