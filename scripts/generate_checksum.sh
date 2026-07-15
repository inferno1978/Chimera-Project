#!/usr/bin/env bash
# ============================================================
# generate_checksum.sh
# Автоматическая генерация SHA256-чексуммы для bootstrap.sh
# ============================================================
# Запускается:
#   1. Вручную: bash scripts/generate_checksum.sh
#   2. Автоматически: Git pre-commit hook (если bootstrap.sh в staged)
#
# Создаёт bootstrap.sh.sha256 в формате sha256sum -c:
#   <hash>  bootstrap.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BOOTSTRAP="$REPO_ROOT/bootstrap.sh"
CHECKSUM_FILE="$REPO_ROOT/bootstrap.sh.sha256"

if [[ ! -f "$BOOTSTRAP" ]]; then
    echo "ERROR: bootstrap.sh не найден в $REPO_ROOT" >&2
    exit 1
fi

# Вычисляем SHA256 (используем sha256sum — стандартный инструмент)
HASH=$(sha256sum "$BOOTSTRAP" | awk '{print $1}')
SIZE=$(stat -c%s "$BOOTSTRAP" 2>/dev/null || stat -f%z "$BOOTSTRAP" 2>/dev/null || echo "?")

# Записываем в формате sha256sum -c
# Формат: <64-char-hash>  <filename>
# Два пробела — это стандарт sha256sum (text mode)
printf '%s  bootstrap.sh\n' "$HASH" > "$CHECKSUM_FILE"

echo "✓ bootstrap.sh.sha256 сгенерирован"
echo "  SHA256: $HASH"
echo "  Размер: $SIZE байт"
echo "  Файл: $CHECKSUM_FILE"

# Если запущено из pre-commit hook — stage файл
if [[ "${GIT_HOOK_MODE:-}" == "1" ]]; then
    git add "$CHECKSUM_FILE"
    echo "  → Staged для коммита (pre-commit hook)"
fi
