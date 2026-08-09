#!/usr/bin/env python3
"""
chimera/scripts/generate_olcrtc_password_hash.py
───────────────────────────────────────────────────────────────────────────────
Утилита для админа: устанавливает/меняет пароль для скрытого меню olcRTC.

БЕЗОПАСНАЯ МОДЕЛЬ (state-file, не исходник):
  • Хеш пароля хранится ТОЛЬКО в state-файле на сервере:
        /var/lib/xray-installer/olcrtc_access.hash  (chmod 0600, root)
  • Хеш НИКОГДА не попадает в исходники и не коммитится в git.
  • Алгоритм — PBKDF2-HMAC-SHA256 со случайной солью 16 байт и
    600000 итераций (OWASP 2025-2026).
  • Формат файла — JSON:
        {"salt": "<hex>", "hash": "<hex>",
         "iterations": N, "algo": "pbkdf2_sha256"}

ИСПОЛЬЗОВАНИЕ:
    sudo python3 chimera/scripts/generate_olcrtc_password_hash.py

    (нужен root для записи в /var/lib/xray-installer/ и chmod 0600)
"""
import getpass
import hashlib
import json
import os
import sys
from pathlib import Path

HASH_FILE = Path("/var/lib/xray-installer/olcrtc_access.hash")
ITERATIONS = 600_000
ALGO = "pbkdf2_sha256"
MIN_LENGTH = 8


def _check_password_strength(pwd: str) -> list[str]:
    """Возвращает список замечаний. Пустой список = пароль OK."""
    issues = []
    if len(pwd) < MIN_LENGTH:
        issues.append(f"длина < {MIN_LENGTH} символов")
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

    print("=== Установка пароля для скрытого меню olcRTC ===")
    print()

    pwd1 = getpass.getpass("Новый пароль: ")
    pwd2 = getpass.getpass("Повтор пароля: ")

    if pwd1 != pwd2:
        print("Ошибка: пароли не совпадают.", file=sys.stderr)
        sys.exit(1)

    issues = _check_password_strength(pwd1)
    if issues:
        print(f"Ошибка: пароль слишком слабый ({'; '.join(issues)}).", file=sys.stderr)
        sys.exit(1)

    salt = os.urandom(16)
    computed = hashlib.pbkdf2_hmac("sha256", pwd1.encode("utf-8"), salt, ITERATIONS).hex()

    data = {
        "salt": salt.hex(),
        "hash": computed,
        "iterations": ITERATIONS,
        "algo": ALGO,
    }

    HASH_FILE.parent.mkdir(parents=True, exist_ok=True)
    HASH_FILE.write_text(json.dumps(data, indent=2))
    HASH_FILE.chmod(0o600)

    print()
    print(f"✓ Пароль установлен в {HASH_FILE}")
    print(f"  Алгоритм: {ALGO}, итераций: {ITERATIONS}")
    print()
    print("Теперь ввод 'olcrtc' в главном меню запросит этот пароль.")


if __name__ == "__main__":
    main()
