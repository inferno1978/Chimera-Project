#!/usr/bin/env bash
# Direct CSQTT build script — обходит fetch_package и запускает post_install
# напрямую на /root/csqtt-main.tar.gz с подробным выводом.
#
# Запуск на VPS: bash chimera-csqtt-direct-build.sh
# Скрипт покажет, на каком именно этапе падает сборка.

set -e

echo "=== Direct CSQTT build diagnostic ==="
echo "Date: $(date)"
echo "Host: $(hostname)"
echo

# Проверим что файл на месте
if [[ ! -f /root/csqtt-main.tar.gz ]]; then
    echo "✗ Файл /root/csqtt-main.tar.gz не найден!"
    echo "  Сначала скачайте его: bash chimera-csqtt-manual-download.sh"
    exit 1
fi

SIZE=$(stat -c%s /root/csqtt-main.tar.gz)
MAGIC=$(od -A n -t x1 -N 2 /root/csqtt-main.tar.gz | tr -d ' ')
echo "✓ Файл найден: /root/csqtt-main.tar.gz"
echo "  Размер: $SIZE байт"
echo "  Gzip magic: $MAGIC"
if [[ "$MAGIC" != "1f8b" ]]; then
    echo "  ✗ Файл НЕ gzip! Это HTML или другой формат."
    exit 1
fi
echo

# Удалим старый /tmp/csqtt_packages (если остался от прошлой попытки)
rm -rf /tmp/csqtt_packages /tmp/csqtt_build

# Запустим post_install напрямую через python3
echo "=== Запуск post_install напрямую ==="
cd /opt/chimera
python3 << 'PYEOF'
import sys
import traceback
from pathlib import Path

print("[1] Импортирую модули Chimera...")
try:
    from chimera.modules.csqtt_packages import CSQTT_SOURCE_SPEC, _post_install_csqtt_source
    from chimera.modules.download_manager import _default_copy_to_dests
    print("    ✓ Импорт OK")
except Exception as e:
    print(f"    ✗ Импорт FAILED: {e}")
    traceback.print_exc()
    sys.exit(1)

src = Path("/root/csqtt-main.tar.gz")
print(f"\n[2] src файл: {src}")
print(f"    exists: {src.exists()}")
print(f"    size:   {src.stat().st_size}")

print(f"\n[3] install_dests: {CSQTT_SOURCE_SPEC.install_dests}")

# Сначала копируем файл в install_dests (как сделал бы fetch_package)
print("\n[4] Копирую файл в install_dests (/tmp/csqtt_packages/)...")
try:
    _default_copy_to_dests(src, CSQTT_SOURCE_SPEC.install_dests)
    print("    ✓ Скопировано")
except Exception as e:
    print(f"    ✗ Копирование FAILED: {e}")
    traceback.print_exc()
    sys.exit(1)

# Теперь вызываем post_install с подробным выводом
print("\n[5] Запускаю _post_install_csqtt_source...")
print("    (это может занять 5-20 минут — сборка Rust)")
try:
    result = _post_install_csqtt_source(src, CSQTT_SOURCE_SPEC.install_dests)
    print(f"\n[6] post_install вернул: {result}")
    if result:
        print("    ✓ УСПЕХ! CSQTT собран.")
        print(f"    Binary: /usr/local/bin/csqtt-server")
        # Проверим что binary появился
        bin_path = Path("/usr/local/bin/csqtt-server")
        if bin_path.exists():
            print(f"    ✓ Binary существует: {bin_path} ({bin_path.stat().st_size} байт)")
        else:
            print(f"    ⚠ Binary НЕ найден: {bin_path}")
    else:
        print("    ✗ post_install вернул False — сборка упала.")
        print("    Смотрите вывод выше — там должна быть строка [ERR].")
except Exception as e:
    print(f"\n[6] ✗ post_install поднял исключение: {e}")
    traceback.print_exc()
    sys.exit(1)
PYEOF

echo
echo "=== Diagnostic complete ==="
echo
echo "Если сборка упала на этапе [5] — смотрите вывод выше."
echo "Там будет конкретная ошибка (Rust/Zig/cargo/compile error)."
echo
echo "Возможные причины:"
echo "  - Rust не установлен (нужно ~500 MB свободного места)"
echo "  - Zig не установлен (нужно ~200 MB)"  
echo "  - cargo-zigbuild не установлен"
echo "  - OOM (мало RAM/swap) — проверьте: free -m"
echo "  - Нет места на диске — проверьте: df -h"
echo
echo "Запустите эти команды и пришлите вывод:"
echo "  free -m"
echo "  df -h /"
echo "  ls -la /root/.cargo/bin/ 2>/dev/null | head -10"
echo "  ls -la /usr/local/bin/zig 2>/dev/null"
echo "  which cargo zig cargo-zigbuild"
