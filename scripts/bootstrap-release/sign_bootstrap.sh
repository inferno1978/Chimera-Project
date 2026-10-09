#!/usr/bin/env bash
# ============================================================
# sign_bootstrap.sh — подписание bootstrap.sh ключом Ed25519
# ============================================================
# Релизный процесс публикации: ТОЛЬКО через этот скрипт меняется
# bootstrap.sh.sig. Приватный ключ НИКОГДА не хранится в репозитории
# (защита от утечки через git) и не логируется.
#
# Использование:
#   CHIMERA_SIGN_KEY=/путь/к/chimera-bootstrap-ed25519.pem \
#       bash scripts/bootstrap-release/sign_bootstrap.sh
#
# Где должен лежать ключ:
#   - вне клонов репозитория (например /root/.signing/ на машине релизера)
#   - копия на сервере Forgejo: /etc/chimera-mirror/bootstrap-signing-key.pem (root:600)
#
# После подписи: git add bootstrap.sh bootstrap.sh.sig && git commit
# (pre-commit hook проверит подпись staged-версии автоматически).
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEY="${CHIMERA_SIGN_KEY:-}"
PUB="$ROOT/scripts/bootstrap-release/bootstrap.pub"
BOOT="$ROOT/bootstrap.sh"
SIG="$ROOT/bootstrap.sh.sig"

[ -n "$KEY" ] || { echo "ERROR: задайте CHIMERA_SIGN_KEY=/путь/к/приватному-ключу.pem" >&2; exit 1; }
[ -f "$KEY" ] || { echo "ERROR: файл ключа не найден: $KEY" >&2; exit 1; }
[ -f "$BOOT" ] || { echo "ERROR: bootstrap.sh не найден" >&2; exit 1; }
[ -f "$PUB" ]  || { echo "ERROR: публичный ключ не найден: $PUB" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl не найден" >&2; exit 1; }

# Приватный ключ не должен лежать внутри репозитория (риск случайного коммита).
KEY_ABS="$(cd "$(dirname "$KEY")" && pwd)/$(basename "$KEY")"
case "$KEY_ABS" in
    "$ROOT"/*|"$ROOT")
        echo "ERROR: приватный ключ находится внутри репозитория ($KEY_ABS) — ЗАПРЕЩЕНО." >&2
        echo "       Перенесите ключ вне клона (например /root/.signing/) и повторите." >&2
        exit 1 ;;
esac

# Подпись (raw Ed25519, 64 байта) и немедленная перекрёстная проверка
# публичным ключом из репозитория — ловит рассинхрон пары ключей.
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$BOOT" -out "$SIG"
openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$BOOT" -sigfile "$SIG" >/dev/null

echo "OK: подписано — bootstrap.sh.sig ($(wc -c < "$SIG") байт)"
echo "  SHA256 bootstrap.sh:      $(sha256sum "$BOOT" | cut -d' ' -f1)"
echo "  Отпечаток pub (sha256 DER): $(openssl pkey -pubin -in "$PUB" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
echo "  Далее: git add bootstrap.sh bootstrap.sh.sig && git commit"
