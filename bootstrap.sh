#!/usr/bin/env bash
# ============================================================
#  Chimera Project v5.0.0 — Bootstrap
#  Multi-Protocol Anti-DPI Installer
#  bash <(curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh)
# ============================================================
#
# ─── INTEGRITY VERIFICATION ─────────────────────────────────────
# SHA256 этого файла публикуется в bootstrap.sh.sha256 (рядом).
# Проверить целостность перед запуском:
#
#   curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh -o /tmp/bootstrap.sh
#   curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh.sha256 -o /tmp/bootstrap.sh.sha256
#   cd /tmp && sha256sum -c bootstrap.sh.sha256
#
# Или одной командой (без зависимости от имени файла):
#   [ "$(curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh | sha256sum | awk '{print $1}')" = "$(curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh.sha256 | awk '{print $1}')" ] && echo "OK" || echo "MISMATCH"
#
# SHA256 генерируется автоматически при каждом коммите (pre-commit hook).
# ────────────────────────────────────────────────────────────────
set -euo pipefail

# Сброс системного прокси перед загрузкой — защита от сломанных окружений,
# когда в /etc/environment прописан прокси на несуществующий локальный порт.
unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy 2>/dev/null || true

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
err()  { echo -e "  ${RED}✗${NC} $*" >&2; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
info() { echo -e "  ${CYAN}→${NC} $*"; }

echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
 ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
 Chimera Project v5.0.0 — Multi-Protocol Anti-DPI Installer
BANNER
echo -e "${NC}"

# [1] Root check
echo -e "${BOLD}[1/5] Проверка прав${NC}"
if [[ $EUID -ne 0 ]]; then
    err "Требуются права root"
    echo -e "     ${YELLOW}sudo bash <(curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh)${NC}"
    exit 1
fi
ok "root: OK"

# [2] Определение пакетного менеджера
echo -e "\n${BOLD}[2/5] Система${NC}"
if   command -v apt-get &>/dev/null; then PKG_INSTALL="apt-get install -y -q"
elif command -v dnf     &>/dev/null; then PKG_INSTALL="dnf install -y -q"
elif command -v yum     &>/dev/null; then PKG_INSTALL="yum install -y -q"
else err "Не найден поддерживаемый пакетный менеджер"; exit 1; fi
OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
OS_VER=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "?")
ok "ОС: ${OS_ID} ${OS_VER}"

# [3] Минимальные зависимости
echo -e "\n${BOLD}[3/5] Зависимости${NC}"
MISSING=()
command -v python3 &>/dev/null || MISSING+=("python3")
command -v curl    &>/dev/null || MISSING+=("curl")
command -v git     &>/dev/null || MISSING+=("git")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Устанавливаю: ${MISSING[*]}"
    if command -v apt-get &>/dev/null; then apt-get update -qq; fi
    for pkg in "${MISSING[@]}"; do
        $PKG_INSTALL "$pkg" || { err "Не удалось установить ${pkg}"; exit 1; }
    done
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MIN_OK=$(python3 -c "import sys; print(int(sys.version_info >= (3,10)))")
PY_312_OK=$(python3 -c "import sys; print(int(sys.version_info >= (3,12)))")
if [[ "$PY_MIN_OK" != "1" ]]; then
    err "Требуется Python >= 3.10, найден ${PY_VER}"
    exit 1
fi
if [[ "$PY_312_OK" != "1" ]]; then
    warn "Python ${PY_VER} — рекомендуется 3.12+ (Ubuntu 24.04)"
    warn "На Python < 3.12 возможны ошибки вида:"
    warn "  SyntaxError: f-string expression part cannot include a backslash"
    warn "  SyntaxError: f-string: unmatched '('"
    warn "Для обновления Python: https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa"
    echo ""
else
    ok "Python ${PY_VER}: OK"
fi

# [4] Загрузка / обновление
echo -e "\n${BOLD}[4/5] Загрузка Chimera Project${NC}"
INSTALL_DIR="/opt/chimera"
REPO_URL="https://gitlab.com/netwalker071778/chimera-project"
BRANCH="chimera-v5"

# Ищем существующую установку в стандартных системных путях.
# ВАЖНО: домашние директории разработчиков НЕ проверяем — это личные пути,
# бесполезные для конечных пользователей и засветящие структуру окружения.
# Поддерживаемые legacy-пути (для обратной совместимости со старыми установками):
#   - /opt/vless-ultimate     (старый путь до переименования в Chimera Project)
#   - /opt/VLESS-Ultimate-Installer  (старый путь из ранних версий bootstrap)
#   - /opt/chimera            (новый путь — совпадает с INSTALL_DIR)
_found=""
for _candidate in \
    "/opt/vless-ultimate" \
    "/opt/VLESS-Ultimate-Installer" \
    "/opt/chimera"
do
    if [[ -f "${_candidate}/main.py" ]]; then
        _found="$_candidate"
        break
    fi
done
if [[ -n "$_found" && "$_found" != "$INSTALL_DIR" ]]; then
    warn "Найдена существующая установка: ${_found}"
    info "Обновляю её (а не ${INSTALL_DIR})..."
    info "Примечание: путь /opt/chimera — новый стандарт. Если хотите мигрировать,"
    info "          перенесите директорию вручную: mv ${_found} ${INSTALL_DIR}"
    INSTALL_DIR="$_found"
fi

# =============================================================================
#  Atomic archive-based update with staging, verification, and rollback
# =============================================================================
# Безопасный паттерн обновления через archive-tarball:
#   1. Download → tmp file (curl -f, проверка exit code)
#   2. Extract → distinct staging dir (tar, проверка exit code)
#   3. Verify key files exist in staging (main.py, chimera/__init__.py, chimera/_core.py)
#   4. Backup current installation → ${install_dir}.pre-chimera-backup
#   5. Copy staging → install_dir
#   6. Verify import chimera
#   7. If ANY step fails after backup → ROLLBACK from backup
#   8. If all OK → cleanup backup + staging + auto-cleanup vless_installer/
#
# ГАРАНТИЯ: если curl/tar/verify упали ДО backup — install_dir НЕ ТРОНУТ.
#           если cp/import упали ПОСЛЕ backup — install_dir ВОССТАНОВЛЕН из backup.
_archive_update() {
    local install_dir="$1"
    local archive_url="$2"
    local _pid="$$"
    local _archive_tmp="/tmp/chimera_update_${_pid}.tar.gz"
    local _staging="/tmp/chimera_staging_${_pid}"

    # Очистка от предыдущих прогонов
    rm -rf "$_staging" "$_archive_tmp"

    # --- Stage 1: Download ---
    if ! curl -fsSL --connect-timeout 30 --retry 3 -o "$_archive_tmp" "$archive_url" 2>/dev/null; then
        warn "Не удалось скачать архив. Проверьте соединение с GitHub."
        warn "Установка НЕ изменена. Попробуйте вручную:"
        warn "  cd ${install_dir} && git reset --hard origin/${BRANCH}"
        rm -f "$_archive_tmp"
        return 1
    fi
    local _size
    _size=$(stat -c%s "$_archive_tmp" 2>/dev/null || echo "?")
    ok "Архив скачан (${_size} байт)"

    # --- Stage 2: Extract to staging (NOT to install_dir!) ---
    mkdir -p "$_staging"
    if ! tar -xzf "$_archive_tmp" -C "$_staging" 2>/dev/null; then
        warn "Не удалось распаковать архив (возможно повреждён при передаче)."
        warn "Установка НЕ изменена. Попробуйте вручную:"
        warn "  cd ${install_dir} && git reset --hard origin/${BRANCH}"
        rm -rf "$_staging" "$_archive_tmp"
        return 1
    fi
    ok "Архив распакован в staging: ${_staging}"

    # --- Stage 3: Find extracted dir + verify key files ---
    local _extracted=""
    for _d in "${_staging}/chimera-project-${BRANCH}" "${_staging}/Chimera-Project-${BRANCH}" "${_staging}/VLESS-Ultimate-Installer-${BRANCH}"; do
        if [[ -d "$_d" ]]; then _extracted="$_d"; break; fi
    done
    if [[ -z "$_extracted" ]]; then
        warn "Архив распакован, но ожидаемая директория не найдена."
        warn "Установка НЕ изменена. Содержимое staging: $(ls "$_staging" 2>/dev/null)"
        rm -rf "$_staging" "$_archive_tmp"
        return 1
    fi
    # Verify critical files exist in staging
    if [[ ! -f "${_extracted}/main.py" ]] || \
       [[ ! -f "${_extracted}/chimera/__init__.py" ]] || \
       [[ ! -f "${_extracted}/chimera/_core.py" ]]; then
        warn "Архив неполон — отсутствуют ключевые файлы (main.py, chimera/__init__.py, chimera/_core.py)."
        warn "Установка НЕ изменена. Попробуйте вручную:"
        warn "  cd ${install_dir} && git reset --hard origin/${BRANCH}"
        rm -rf "$_staging" "$_archive_tmp"
        return 1
    fi
    ok "Staging проверен: main.py, chimera/__init__.py, chimera/_core.py — на месте"

    # --- Stage 4: Backup current installation ---
    local _backup="${install_dir}.pre-chimera-backup"
    rm -rf "$_backup"
    if ! cp -rf "$install_dir" "$_backup" 2>/dev/null; then
        warn "Не удалось создать backup текущей установки (диск заполнен?)."
        warn "Установка НЕ изменена (безопасность важнее обновления)."
        rm -rf "$_backup" "$_staging" "$_archive_tmp"
        return 1
    fi
    ok "Backup создан: ${_backup}"

    # --- Stage 5: Copy staging → install_dir ---
    if ! cp -rf "${_extracted}/." "${install_dir}/" 2>/dev/null; then
        warn "Копирование файлов прервано (диск заполнен?). ОТКАТ из backup."
        rm -rf "${install_dir}"
        mv "$_backup" "$install_dir"
        ok "Откат выполнен — установка восстановлена из backup"
        rm -rf "$_staging" "$_archive_tmp"
        return 1
    fi
    ok "Файлы скопированы из staging в ${install_dir}"

    # --- Stage 6: Verify import chimera ---
    if ! PYTHONPATH="${install_dir}" python3 -c "import chimera" >/dev/null 2>&1; then
        warn "Импорт chimera не прошёл после обновления. ОТКАТ из backup."
        rm -rf "${install_dir}"
        mv "$_backup" "$install_dir"
        ok "Откат выполнен — установка восстановлена из backup"
        rm -rf "$_staging" "$_archive_tmp"
        warn "Попробуйте вручную: cd ${install_dir} && git reset --hard origin/${BRANCH}"
        return 1
    fi
    ok "Импорт chimera проверен — обновление успешно"

    # --- Stage 7: Cleanup ---
    rm -rf "$_backup" "$_staging" "$_archive_tmp"

    # --- Stage 8: Auto-cleanup old vless_installer/ ---
    if [[ -d "${install_dir}/vless_installer" ]]; then
        rm -rf "${install_dir}/vless_installer"
        ok "Старая директория vless_installer/ удалена (auto-cleanup)"
    fi
    find "${install_dir}" -maxdepth 3 -type d -name "__pycache__" \
        -path "*/vless_installer/*" -exec rm -rf {} + 2>/dev/null || true

    return 0
}

# =============================================================================
#  Основная логика обновления / установки
# =============================================================================
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Обновление существующей git-установки..."
    cd "$INSTALL_DIR"

    # Пробуем обычный git pull. Если упал (divergent branches, нет сети и т.п.) —
    # fallback на полный archive-tarball через _archive_update (atomic, с rollback).
    if git pull --quiet origin "$BRANCH" 2>/dev/null; then
        ok "Обновлено до последней версии (fast-forward)"
    else
        warn "git pull не удался (возможно divergent branches) — полное обновление через archive..."
        # _archive_update может вернуть 1 (graceful failure) — не дадим set -e убить скрипт
        if ! _archive_update "$INSTALL_DIR" "${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"; then
            warn "Обновление через archive не удалось. Установка НЕ изменена."
            warn "Попробуйте вручную: cd ${INSTALL_DIR} && git reset --hard origin/${BRANCH}"
        fi
    fi
else
    if [[ -d "$INSTALL_DIR" ]] && [[ -f "${INSTALL_DIR}/main.py" ]]; then
        # Установка без .git — обновляем через _archive_update (atomic, с rollback)
        info "Установка без git обнаружена — полное обновление через archive..."
        if ! _archive_update "$INSTALL_DIR" "${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"; then
            warn "Обновление через archive не удалось. Установка НЕ изменена."
            warn "Попробуйте вручную: cd ${INSTALL_DIR} && git reset --hard origin/${BRANCH}"
        fi
    else
        info "Клонирование репозитория..."
        if ! git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
            warn "git clone не удался — загружаю архив..."
            mkdir -p "$INSTALL_DIR"
            _ARCHIVE_URL="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
            # Для свежей установки используем упрощённый путь (backup не нужен —
            # INSTALL_DIR пустой, откатываться некуда). Но staging + verify — обязательно.
            _CLONE_TMP="/tmp/chimera_install_$$.tar.gz"
            _CLONE_STAGING="/tmp/chimera_clone_staging_$$"
            rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
            if curl -fsSL --connect-timeout 30 --retry 3 -o "$_CLONE_TMP" "$_ARCHIVE_URL" 2>/dev/null || \
               curl -fsSL --connect-timeout 30 --retry 3 -o "$_CLONE_TMP" \
                 "https://gitlab.com/netwalker071778/chimera-project/-/archive/chimera-v5/chimera-project-chimera-v5.tar.gz" 2>/dev/null; then
                mkdir -p "$_CLONE_STAGING"
                if tar -xzf "$_CLONE_TMP" -C "$_CLONE_STAGING" 2>/dev/null; then
                    _extracted=""
                    for _d in "${_CLONE_STAGING}/chimera-project-${BRANCH}" "${_CLONE_STAGING}/Chimera-Project-${BRANCH}" "${_CLONE_STAGING}/VLESS-Ultimate-Installer-${BRANCH}"; do
                        if [[ -d "$_d" ]]; then _extracted="$_d"; break; fi
                    done
                    if [[ -n "$_extracted" ]] && [[ -f "${_extracted}/main.py" ]]; then
                        cp -r "${_extracted}/." "$INSTALL_DIR/"
                        ok "Загружено в ${INSTALL_DIR}"
                    else
                        err "Архив скачан, но директория или main.py не найдены."
                        rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
                        exit 1
                    fi
                else
                    err "Не удалось распаковать архив."
                    rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
                    exit 1
                fi
                rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
            else
                err "Не удалось загрузить архив. Проверьте соединение."
                rm -f "$_CLONE_TMP"
                exit 1
            fi
        else
            ok "Загружено в ${INSTALL_DIR}"
        fi
    fi
fi

[[ -f "${INSTALL_DIR}/main.py" ]] || { err "main.py не найден в ${INSTALL_DIR}"; exit 1; }

# [5] Запуск
echo -e "\n${BOLD}[5/5] Запуск${NC}"
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Запускаю установщик...${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${DIM}Директория: ${INSTALL_DIR}${NC}"
echo -e "  ${DIM}Лог: /var/log/chimera.log${NC}"
echo ""
cd "$INSTALL_DIR"
exec python3 main.py "$@"
