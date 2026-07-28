#!/usr/bin/env python3
"""
chimera/scripts/generate_cdn_masking_password_hash.py
───────────────────────────────────────────────────────────────────────────────
Утилита для админа: генерирует SHA-256 hash пароля для скрытого меню
«CDN masking» (обход белых списков через Beeline CDN).

ИСПОЛЬЗОВАНИЕ:
    python3 chimera/scripts/generate_cdn_masking_password_hash.py

АЛГОРИТМ:
    1. Админ запускает скрипт.
    2. Вводит новый пароль (без эха, через getpass).
    3. Скрипт проверяет требования:
        - длина ≥ 20 символов
        - есть заглавные буквы
        - есть прописные буквы
        - есть спец. символы (не алфанумерические)
    4. Генерирует SHA-256 hash.
    5. Печатает инструкцию по замене хеша в chimera/modules/xhttp_cdn_masking.py.

ПАРОЛЬ В КОДЕ НИКОГДА НЕ ХРАНИТСЯ — только его SHA-256 hash.
Это однонаправленная функция — восстановить пароль из хеша невозможно.

БЕЗОПАСНОСТЬ:
    • Пароль сообщается платным клиентам отдельно (через защищённый канал).
    • Hash можно опубликовать — он бесполезен без перебора (который для
      20+ символов с спец-символами практически невозможен).
    • Замена хеша в коде = смена пароля (старый пароль перестаёт работать).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import hashlib
import getpass
import re
import sys


MIN_LENGTH = 20


def check_password_strength(password: str) -> tuple[bool, list[str]]:
    """Проверяет пароль на соответствие требованиям.

    Возвращает (ok, errors). ok=True если пароль валиден.
    """
    errors: list[str] = []
    if len(password) < MIN_LENGTH:
        errors.append(f"длина < {MIN_LENGTH} символов (сейчас {len(password)})")
    if not re.search(r"[A-Z]", password):
        errors.append("нет заглавных букв (A-Z)")
    if not re.search(r"[a-z]", password):
        errors.append("нет прописных букв (a-z)")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("нет спец. символов (любой не алфанумерический)")
    return (len(errors) == 0, errors)


def main() -> int:
    print()
    print("=" * 72)
    print("  ГЕНЕРАТОР ХЕША ПАРОЛЯ ДЛЯ CDN MASKING (скрытое меню)")
    print("=" * 72)
    print()
    print(f"Требования к паролю:")
    print(f"  • длина ≥ {MIN_LENGTH} символов")
    print(f"  • заглавные буквы (A-Z)")
    print(f"  • прописные буквы (a-z)")
    print(f"  • спец. символы (любые не алфанумерические)")
    print()

    try:
        pwd = getpass.getpass("Введите новый пароль: ")
    except (EOFError, KeyboardInterrupt):
        print("\nОтменено.")
        return 1

    ok, errors = check_password_strength(pwd)
    if not ok:
        print()
        print("Пароль НЕ соответствует требованиям:")
        for e in errors:
            print(f"  • {e}")
        return 1

    # Повторный ввод для подтверждения
    try:
        pwd2 = getpass.getpass("Повторите пароль: ")
    except (EOFError, KeyboardInterrupt):
        print("\nОтменено.")
        return 1

    if pwd != pwd2:
        print("\nПароли не совпадают.")
        return 1

    # Генерируем SHA-256 hash
    pwd_hash = hashlib.sha256(pwd.encode("utf-8")).hexdigest()

    print()
    print("=" * 72)
    print("  SHA-256 HASH ПАРОЛЯ:")
    print("=" * 72)
    print()
    print(f"    {pwd_hash}")
    print()
    print("=" * 72)
    print("  ИНСТРУКЦИЯ ПО УСТАНОВКЕ:")
    print("=" * 72)
    print()
    print("  1. Откройте файл:")
    print("       chimera/modules/xhttp_cdn_masking.py")
    print()
    print("  2. Найдите строку (секция «СКРЫТОЕ МЕНЮ — защита паролем»):")
    print()
    print('       _CDN_MASKING_PASSWORD_HASH: str = (')
    print('           "<старый хеш>"')
    print('       )')
    print()
    print("  3. Замените старый hash на новый:")
    print()
    print(f"       _CDN_MASKING_PASSWORD_HASH: str = (")
    print(f"           \"{pwd_hash}\"")
    print(f"       )")
    print()
    print("  4. Закоммитьте изменение и запушьте в репозиторий.")
    print()
    print("  5. Сообщите пароль платным клиентам через защищённый канал.")
    print("     ПАРОЛЬ В КОДЕ НЕТ — только хеш. После коммита проверьте,")
    print("     что пароль не остался в shell history:")
    print("       grep -i <your-password> ~/.bash_history  (должно быть пусто)")
    print()
    print("  6. Старый пароль перестанет работать сразу после замены хеша.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
