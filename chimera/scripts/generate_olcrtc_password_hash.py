#!/usr/bin/env python3
"""
chimera/scripts/generate_olcrtc_password_hash.py
───────────────────────────────────────────────────────────────────────────────
Утилита для админа: управление паролями для скрытого меню olcRTC.

Использование:
    sudo python3 chimera/scripts/generate_olcrtc_password_hash.py
        — установить/сменить master-пароль (админ, не протухает)

    sudo python3 chimera/scripts/generate_olcrtc_password_hash.py --init-otp
        — создать OTP (одноразовый пароль для пользователя)

    sudo python3 chimera/scripts/generate_olcrtc_password_hash.py --show-otp
        — показать текущий OTP (если есть и не использован)

    sudo python3 chimera/scripts/generate_olcrtc_password_hash.py --rotate-otp
        — принудительно сгенерировать новый OTP
───────────────────────────────────────────────────────────────────────────────
"""
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from chimera.modules.access_control import (
    init_master, init_otp, get_current_otp, rotate_otp,
)

HASH_FILE = Path("/var/lib/xray-installer/olcrtc_access.hash")


def _check_password_strength(pwd: str) -> list[str]:
    issues = []
    if len(pwd) < 8:
        issues.append("длина < 8 символов")
    if not any(c.isupper() for c in pwd):
        issues.append("нет заглавных букв")
    if not any(c.islower() for c in pwd):
        issues.append("нет прописных букв")
    if not any(not c.isalnum() for c in pwd):
        issues.append("нет спец. символов")
    return issues


def main():
    if os.geteuid() != 0:
        print("Ошибка: нужен root (sudo).", file=sys.stderr)
        sys.exit(1)

    args = sys.argv[1:]

    if "--show-otp" in args:
        otp = get_current_otp(HASH_FILE)
        if otp:
            print(f"Текущий OTP: {otp}")
            print("(действителен до первого использования)")
        else:
            print("Нет активного OTP. Создайте: --init-otp или --rotate-otp")
        return

    if "--rotate-otp" in args:
        otp = rotate_otp(HASH_FILE)
        if otp:
            print(f"Новый OTP: {otp}")
            print("Передайте его пользователю. После использования OTP протухнет,")
            print("будет автоматически сгенерирован новый.")
        else:
            print("Ошибка: не удалось создать OTP.", file=sys.stderr)
            sys.exit(1)
        return

    if "--init-otp" in args:
        otp = init_otp(HASH_FILE)
        if otp:
            print(f"OTP создан: {otp}")
            print("Передайте его пользователю. После использования OTP протухнет,")
            print("будет автоматически сгенерирован новый.")
            print()
            print("Посмотреть текущий OTP: sudo python3", sys.argv[0], "--show-otp")
        else:
            print("Ошибка: не удалось создать OTP.", file=sys.stderr)
            sys.exit(1)
        return

    # Default: set master password.
    print("=== Установка master-пароля для скрытого меню olcRTC ===")
    print("(Master-пароль не протухает. Для одноразовых паролей используйте --init-otp)")
    print()

    pwd1 = getpass.getpass("Новый master-пароль: ")
    pwd2 = getpass.getpass("Повтор пароля: ")

    if pwd1 != pwd2:
        print("Ошибка: пароли не совпадают.", file=sys.stderr)
        sys.exit(1)

    issues = _check_password_strength(pwd1)
    if issues:
        print(f"Ошибка: пароль слишком слабый ({'; '.join(issues)}).", file=sys.stderr)
        sys.exit(1)

    if init_master(HASH_FILE, pwd1):
        print(f"\n✓ Master-пароль установлен в {HASH_FILE}")
        print()
        print("Для создания одноразового пароля (OTP) для пользователя:")
        print(f"  sudo python3 {sys.argv[0]} --init-otp")
        print()
        print("Для просмотра текущего OTP:")
        print(f"  sudo python3 {sys.argv[0]} --show-otp")
    else:
        print("Ошибка: не удалось сохранить.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
