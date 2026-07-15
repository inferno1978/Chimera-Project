#!/usr/bin/env python3
"""
test_bootstrap_checksum.py
============================
Регрессионный тест целостности bootstrap.sh SHA256.

Проверяет:
1. bootstrap.sh.sha256 существует и валиден (формат sha256sum -c)
2. SHA256 из .sha256 файла СОВПАДАЕТ с реальным SHA256 bootstrap.sh
   (вычисляется независимо через Python hashlib, не через generate_checksum.sh)
3. sha256sum -c проходит (через subprocess, независимый путь)
4. Тест ПАДАЕТ, если кто-то изменил bootstrap.sh и забыл перегенерировать .sha256

Дополнительно:
5. Симуляция подмены: изменяем bootstrap.sh → тест должен ПАСТЬ
6. Симуляция восстановления: регенерируем .sha256 → тест должен ПРОЙТИ
"""
import sys
import os
import hashlib
import subprocess
import shutil
import tempfile
from pathlib import Path

REPO_ROOT = Path("/home/z/my-project/VLESS-Ultimate-Installer")
BOOTSTRAP = REPO_ROOT / "bootstrap.sh"
CHECKSUM_FILE = REPO_ROOT / "bootstrap.sh.sha256"

GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BOLD = '\033[1m'
NC = '\033[0m'

passed = 0
failed = 0

def ok(msg):
    global passed; passed += 1
    print(f"  {GREEN}✓{NC} {msg}")

def fail(msg):
    global failed; failed += 1
    print(f"  {RED}✗{NC} {msg}")

def section(title):
    print(f"\n{BOLD}{'━' * 60}{NC}")
    print(f"{BOLD}  {title}{NC}")
    print(f"{BOLD}{'━' * 60}{NC}")


def compute_sha256_py(filepath):
    """Независимое вычисление SHA256 через Python hashlib."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def read_checksum_from_file(filepath):
    """Чтение SHA256 из .sha256 файла (формат: <hash>  <filename>)."""
    content = filepath.read_text().strip()
    # Формат sha256sum: <64-char-hex>  <filename>
    parts = content.split(None, 1)
    if len(parts) < 1:
        return None
    return parts[0].strip()


def run_sha256sum_c(bootstrap_path, checksum_path):
    """Запуск sha256sum -c через subprocess (независимый путь проверки)."""
    # sha256sum -c ожидает файл с форматом <hash>  <filename>
    # Но путь в .sha256 файле = "bootstrap.sh", а реальный файл может быть в другом месте.
    # Создаём временный .sha256 с правильным путём.
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sha256', delete=False) as tmp:
        hash_val = read_checksum_from_file(checksum_path)
        tmp.write(f"{hash_val}  {bootstrap_path}\n")
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            ["sha256sum", "-c", tmp_path],
            capture_output=True, text=True
        )
        return result.returncode == 0, result.stdout.strip()
    finally:
        os.unlink(tmp_path)


def main():
    print(f"{BOLD}{'=' * 60}{NC}")
    print(f"{BOLD}  ТЕСТ ЦЕЛОСТНОСТИ bootstrap.sh SHA256{NC}")
    print(f"{BOLD}{'=' * 60}{NC}")
    print(f"bootstrap.sh:       {BOOTSTRAP}")
    print(f"bootstrap.sh.sha256: {CHECKSUM_FILE}")

    # === ТЕСТ 1: Файлы существуют ===
    section("Тест 1: Файлы существуют и валидны")

    if not BOOTSTRAP.exists():
        fail("bootstrap.sh не найден")
        return 1
    ok("bootstrap.sh существует")

    if not CHECKSUM_FILE.exists():
        fail("bootstrap.sh.sha256 не найден — забыл сгенерировать!")
        fail("  Запусти: bash scripts/generate_checksum.sh && git add bootstrap.sh.sha256")
        return 1
    ok("bootstrap.sh.sha256 существует")

    # Проверка формата .sha256
    checksum_content = CHECKSUM_FILE.read_text().strip()
    checksum_from_file = read_checksum_from_file(CHECKSUM_FILE)
    if checksum_from_file is None or len(checksum_from_file) != 64:
        fail(f"Невалидный SHA256 в .sha256 файле: {checksum_from_file}")
        return 1
    ok(f"SHA256 из файла: {checksum_from_file[:16]}...{checksum_from_file[-8:]}")

    # === ТЕСТ 2: Независимое вычисление SHA256 (Python hashlib) ===
    section("Тест 2: Независимое вычисление SHA256 (Python hashlib)")

    actual_sha256 = compute_sha256_py(BOOTSTRAP)
    ok(f"Реальный SHA256: {actual_sha256[:16]}...{actual_sha256[-8:]}")

    if actual_sha256 == checksum_from_file:
        ok(f"{GREEN}✓ СОВПАДАЕТ — чексумма актуальна{NC}")
    else:
        fail(f"{RED}✗ РАСХОЖДЕНИЕ!{NC}")
        fail(f"  В .sha256 файле: {checksum_from_file}")
        fail(f"  Реальный:        {actual_sha256}")
        fail(f"  → Кто-то изменил bootstrap.sh и забыл перегенерировать .sha256!")
        fail(f"  → Запусти: bash scripts/generate_checksum.sh && git add bootstrap.sh.sha256")
        # Не возвращаем 1 сразу — продолжаем остальные тесты

    # === ТЕСТ 3: sha256sum -c (через subprocess, независимый путь) ===
    section("Тест 3: sha256sum -c (subprocess)")

    success, output = run_sha256sum_c(str(BOOTSTRAP), CHECKSUM_FILE)
    print(f"  Вывод: {output}")
    if success:
        ok("sha256sum -c: PASS")
    else:
        fail("sha256sum -c: FAIL")

    # === ТЕСТ 4: Симуляция подмены (тест должен ПАСТЬ) ===
    section("Тест 4: Симуляция подмены bootstrap.sh (ожидаем FAIL)")

    # Сохраняем оригинал
    original_content = BOOTSTRAP.read_bytes()
    # Делаем копию .sha256
    original_checksum = CHECKSUM_FILE.read_text()

    # Модифицируем bootstrap.sh (добавляем строку в конец)
    modified_content = original_content + b"\n# TAMPERED FOR TEST\n"
    BOOTSTRAP.write_bytes(modified_content)

    # Вычисляем SHA256 модифицированного файла
    tampered_sha256 = compute_sha256_py(BOOTSTRAP)
    ok(f"Модифицированный SHA256: {tampered_sha256[:16]}...{tampered_sha256[-8:]}")

    if tampered_sha256 != checksum_from_file:
        ok(f"{GREEN}✓ Расхождение обнаружено (ожидаемо — файл подменён){NC}")
    else:
        fail("Хеши совпали после подмены — что-то не так с тестом")

    # sha256sum -c должен провалиться
    success_tampered, output_tampered = run_sha256sum_c(str(BOOTSTRAP), CHECKSUM_FILE)
    print(f"  Вывод: {output_tampered}")
    if not success_tampered:
        ok("sha256sum -c: FAIL (ожидаемо — файл подменён)")
    else:
        fail("sha256sum -c: PASS — НЕ ожидалось (подмена не обнаружена!)")

    # Восстанавливаем оригинал
    BOOTSTRAP.write_bytes(original_content)

    # Проверяем, что восстановили правильно
    restored_sha256 = compute_sha256_py(BOOTSTRAP)
    if restored_sha256 == actual_sha256:
        ok("Оригинал восстановлен корректно")
    else:
        fail("Не удалось восстановить оригинал!")
        return 1

    # === ТЕСТ 5: Симуляция восстановления (регенерация .sha256) ===
    section("Тест 5: Регенерация .sha256 после изменения (ожидаем PASS)")

    # Изменяем bootstrap.sh легитимно
    BOOTSTRAP.write_bytes(original_content + b"\n# LEGIT CHANGE\n")
    # Регенерируем .sha256
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "generate_checksum.sh")],
        capture_output=True, text=True, cwd=str(REPO_ROOT)
    )
    if result.returncode == 0:
        ok("generate_checksum.sh отработал")
    else:
        fail(f"generate_checksum.sh упал: {result.stderr}")
        BOOTSTRAP.write_bytes(original_content)
        CHECKSUM_FILE.write_text(original_checksum)
        return 1

    # Теперь SHA256 должен совпадать
    new_actual_sha256 = compute_sha256_py(BOOTSTRAP)
    new_checksum_from_file = read_checksum_from_file(CHECKSUM_FILE)

    if new_actual_sha256 == new_checksum_from_file:
        ok(f"{GREEN}✓ После регенерации: SHA256 совпадает{NC}")
    else:
        fail(f"После регенерации: расхождение!")
        fail(f"  Реальный: {new_actual_sha256}")
        fail(f"  В файле:  {new_checksum_from_file}")

    # sha256sum -c должен пройти
    success_regen, output_regen = run_sha256sum_c(str(BOOTSTRAP), CHECKSUM_FILE)
    print(f"  Вывод: {output_regen}")
    if success_regen:
        ok("sha256sum -c: PASS (после регенерации)")
    else:
        fail("sha256sum -c: FAIL (после регенерации — что-то не так)")

    # Восстанавливаем оригинал
    BOOTSTRAP.write_bytes(original_content)
    # Регенерируем .sha256 для оригинала
    subprocess.run(["bash", str(REPO_ROOT / "scripts" / "generate_checksum.sh")],
                   capture_output=True, cwd=str(REPO_ROOT))
    ok("Оригинал восстановлен, .sha256 перегенерирован")

    # === ТЕСТ 6: Pre-commit hook работает ===
    section("Тест 6: Pre-commit hook автогенерация")

    hook_path = REPO_ROOT / ".githooks" / "pre-commit"
    if hook_path.exists():
        ok("pre-commit hook существует")
    else:
        fail("pre-commit hook не найден")
        return 1

    # Проверяем, что hooksPath настроен
    result = subprocess.run(
        ["git", "config", "core.hooksPath"],
        capture_output=True, text=True, cwd=str(REPO_ROOT)
    )
    if result.stdout.strip() == ".githooks":
        ok("git config core.hooksPath = .githooks")
    else:
        fail(f"core.hooksPath = '{result.stdout.strip()}' (ожидалось '.githooks')")

    # Проверяем, что hook исполняемый
    if os.access(str(hook_path), os.X_OK):
        ok("pre-commit hook исполняемый")
    else:
        fail("pre-commit hook НЕ исполняемый")

    # === ИТОГ ===
    print(f"\n{BOLD}{'=' * 60}{NC}")
    print(f"{BOLD}  ИТОГ{NC}")
    print(f"{BOLD}{'=' * 60}{NC}")
    print(f"  {GREEN}✓ Успешно: {passed}{NC}")
    if failed:
        print(f"  {RED}✗ Ошибок:  {failed}{NC}")
        print(f"\n  {RED}{BOLD}⚠️  РАСХОЖДЕНИЕ SHA256 — перегенерируй:{NC}")
        print(f"  {RED}  bash scripts/generate_checksum.sh && git add bootstrap.sh.sha256{NC}")
        return 1
    else:
        print(f"\n  {GREEN}{BOLD}✓ bootstrap.sh SHA256 актуален{NC}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
