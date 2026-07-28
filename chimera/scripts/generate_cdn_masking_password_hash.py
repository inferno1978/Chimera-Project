#!/usr/bin/env python3
"""
chimera/scripts/generate_cdn_masking_password_hash.py
───────────────────────────────────────────────────────────────────────────────
Утилита для админа: устанавливает/меняет пароль для скрытого меню
«CDN masking» (обход белых списков через Beeline CDN).

БЕЗОПАСНАЯ МОДЕЛЬ (state-file, не исходник):
  • Хеш пароля хранится ТОЛЬКО в state-файле на сервере:
        /var/lib/xray-installer/cdn_premium.hash  (chmod 0600, root)
  • Хеш НИКОГДА не попадает в исходники и не коммитится в git.
  • Алгоритм — PBKDF2-HMAC-SHA256 со случайной солью 16 байт и
    600000 итераций (OWASP 2025-2026).
  • Формат файла — JSON:
        {"salt": "<hex>", "hash": "<hex>",
         "iterations": N, "algo": "pbkdf2_sha256"}
    Параметры iterations и algo хранятся в файле, чтобы в будущем
    можно было поднять N без поломки старых хешей.
  • Каждая установка генерирует НОВУЮ случайную соль — два прогона
    одного и того же пароля дают РАЗНЫЕ salt и РАЗНЫЕ hash.

ИСПОЛЬЗОВАНИЕ:
    sudo python3 chimera/scripts/generate_cdn_masking_password_hash.py

    (нужен root для записи в /var/lib/xray-installer/ и chmod 0600)

АЛГОРИТМ:
    1. Админ запускает скрипт.
    2. Вводит новый пароль дважды (без эха, через getpass).
    3. Скрипт проверяет требования:
        - длина ≥ 20 символов
        - есть заглавные буквы
        - есть прописные буквы
        - есть спец. символы (не алфанумерические)
    4. Генерирует salt = os.urandom(16).
    5. Вычисляет hash = pbkdf2_hmac("sha256", password, salt, 600000).hex().
    6. Записывает JSON в /var/lib/xray-installer/cdn_premium.hash.
    7. chmod 0600, владелец root.
    8. Печатает подтверждение — БЕЗ упоминания git/commit/push.

ПАРОЛЬ В КОДЕ НИКОГДА НЕ ХРАНИТСЯ — даже хеш не в коде.
Plaintext-пароль админ сообщает платным клиентам через защищённый
канал (Signal, Telegram secret chat, и т.п. — НЕ через git, НЕ через
открытые чаты).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import sys
from pathlib import Path


MIN_LENGTH = 20

# PBKDF2-HMAC-SHA256 с 600000 итераций — актуальная рекомендация OWASP
# для 2025-2026. Должно совпадать со значением в xhttp_cdn_masking.py
# (только для НОВЫХ файлов; старые читают iterations из JSON).
ITERATIONS = 600_000

# Алгоритм. Хранится в файле — при будущем переходе на argon2/scrypt
# старые файлы можно отличить по этому полю.
ALGO = "pbkdf2_sha256"

# Путь к state-файлу. Должен совпадать с CDN_MASKING_HASH_FILE в
# chimera/modules/xhttp_cdn_masking.py. Дублируем сюда константой,
# чтобы скрипт не зависел от импорта модуля (он может запускаться
# до установки Chimera).
HASH_FILE = Path("/var/lib/xray-installer/cdn_premium.hash")


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


def write_hash_file(password: str, dest: Path = HASH_FILE,
                    iterations: int = ITERATIONS) -> dict:
    """Генерирует salt+hash и записывает JSON в dest.

    Возвращает записанный dict (для тестов и инспекции).
    НЕ логирует plaintext-пароль. После записи файл получает chmod 0600.

    Аргументы:
        password   — plaintext-пароль (уже проверенный на сложность).
        dest       — целевой путь (по умолч. HASH_FILE).
        iterations — число итераций PBKDF2 (по умолч. ITERATIONS=600000).

    Исключения:
        OSError — нет прав на запись, нет каталога, и т.п.
                  (вызывающая сторона решает как реагировать).
    """
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    ).hex()
    data = {
        "salt": salt.hex(),
        "hash": pwd_hash,
        "iterations": iterations,
        "algo": ALGO,
    }
    # Создаём каталог если его нет (аналогично _core.py строка 490-491).
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Атомарная запись: пишем во временный файл, потом rename — чтобы
    # при сбое посреди записи не осталось битого файла.
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    # Если запущено под root — явно выставляем владельца root:root.
    # (os.chown может бросить если не root — тогда просто пропускаем,
    #  права 0600 уже выставлены через chmod.)
    try:
        os.chown(tmp, 0, 0)
    except (PermissionError, OSError):
        pass
    tmp.replace(dest)
    return data


def main() -> int:
    print()
    print("=" * 72)
    print("  УСТАНОВКА ПАРОЛЯ CDN MASKING (скрытое меню, PBKDF2 state-file)")
    print("=" * 72)
    print()
    print(f"Требования к паролю:")
    print(f"  • длина ≥ {MIN_LENGTH} символов")
    print(f"  • заглавные буквы (A-Z)")
    print(f"  • прописные буквы (a-z)")
    print(f"  • спец. символы (любые не алфанумерические)")
    print()
    print(f"Хеш будет записан в:")
    print(f"  {HASH_FILE}")
    print(f"  (chmod 0600, root; алгоритм: PBKDF2-HMAC-SHA256, {ITERATIONS} итераций)")
    print()

    # Проверка, что запущено под root (нужно для записи в /var/lib/...).
    if os.geteuid() != 0:
        print(f"⚠️  Внимание: скрипт запущен НЕ под root.")
        print(f"   Запись в {HASH_FILE} может не получиться.")
        print(f"   Рекомендуется: sudo python3 chimera/scripts/generate_cdn_masking_password_hash.py")
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

    # Повторный ввод для подтверждения.
    try:
        pwd2 = getpass.getpass("Повторите пароль: ")
    except (EOFError, KeyboardInterrupt):
        print("\nОтменено.")
        return 1

    if pwd != pwd2:
        print("\nПароли не совпадают.")
        return 1

    # Записываем hash-файл.
    try:
        data = write_hash_file(pwd)
    except OSError as e:
        print()
        print(f"❌ Ошибка записи в {HASH_FILE}: {e}")
        print(f"   Проверьте, что запущены под root и каталог существует.")
        return 1

    # Очистка plaintext-пароля из памяти (best-effort; Python не гарантирует
    # немедленную очистку строк из-за intern, но это лучший доступный ход).
    del pwd
    del pwd2

    print()
    print("=" * 72)
    print("  ✅  ПАРОЛЬ УСТАНОВЛЕН")
    print("=" * 72)
    print()
    print(f"  Файл:        {HASH_FILE}")
    print(f"  Алгоритм:    {data['algo']}")
    print(f"  Итераций:    {data['iterations']}")
    print(f"  Соль (hex):  {data['salt']}")
    print(f"  Hash (hex):  {data['hash'][:32]}…{data['hash'][-16:]}")
    print(f"  Права:       0600 (root)")
    print()
    print("=" * 72)
    print("  СОВЕТЫ ПО БЕЗОПАСНОСТИ:")
    print("=" * 72)
    print()
    print("  • Пароль сообщите платным клиентам через защищённый канал")
    print("    (Signal, Telegram secret chat, и т.п.).")
    print("  • НЕ передавайте пароль через git, открытые чаты, email.")
    print("  • Проверьте, что пароль не остался в shell history:")
    print("      grep -i <your-password> ~/.bash_history  (должно быть пусто)")
    print("  • Старый пароль перестаёт работать сразу после перезаписи файла.")
    print("  • Для смены пароля — запустите скрипт повторно (новая соль).")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
