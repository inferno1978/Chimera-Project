#!/usr/bin/env bash
# ============================================================
#  Chimera Project v5.0.0 — Bootstrap
#  Multi-Protocol Anti-DPI Installer
#  bash <(curl -fsSL https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh)
#
#  Универсальная команда с авто-fallback (Forgejo → GitLab → GitHub):
#  bash <(curl -fsSL https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh \
#      || curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh \
#      || curl -fsSL https://raw.githubusercontent.com/inferno1978/Chimera-Project/main/bootstrap.sh)
#
#  ENV-переопределения источника загрузки репозитория:
#    CHIMERA_MIRROR — forgejo (по умолчанию) | gitlab | github | <URL кастомного зеркала>
#        (напр. https://host.example/owner/repo.git или ssh://root@1.2.3.4/srv/git/chimera.git)
#    CHIMERA_BRANCH — ветка; авто по умолчанию: main для forgejo и github,
#        chimera-v5 для gitlab и кастомного зеркала (при своём зеркале переопределяйте явно)
#  При сбое источника (clone/pull/archive timeout или ошибка) — автоматический
#  fallback на следующее зеркало: forgejo→gitlab→github (по умолчанию);
#  gitlab→forgejo→github; github→forgejo→gitlab; кастом→forgejo→gitlab→github.
#  Каждая попытка логируется. Кастомное зеркало — только git clone (tar.gz может
#  не отдаваться), проверка bootstrap.sh.sha256 пропускается (WARN в логе).
# ============================================================
#
# ─── INTEGRITY VERIFICATION ─────────────────────────────────────
# SHA256 этого файла публикуется в bootstrap.sh.sha256 (рядом).
# Проверить целостность перед запуском:
#
#   curl -fsSL https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh -o /tmp/bootstrap.sh
#   curl -fsSL https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh.sha256 -o /tmp/bootstrap.sh.sha256
#   cd /tmp && sha256sum -c bootstrap.sh.sha256
#
# Или одной командой (без зависимости от имени файла):
#   [ "$(curl -fsSL https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh | sha256sum | awk '{print $1}')" = "$(curl -fsSL https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh.sha256 | awk '{print $1}')" ] && echo "OK" || echo "MISMATCH"
#
# То же для зеркал — замените оба URL на:
#   GitHub: https://raw.githubusercontent.com/inferno1978/Chimera-Project/main/bootstrap.sh(.sha256)
#   GitLab: https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh(.sha256)
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
    echo -e "     ${YELLOW}sudo bash <(curl -fsSL https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh)${NC}"
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

# >>> CHIMERA MIRRORS (мульти-источник; проверяется tests/test_bootstrap_mirrors.py)
# Переопределение через окружение (см. шапку файла):
#   CHIMERA_MIRROR — forgejo (по умолчанию) | gitlab | github | <URL кастомного зеркала>
#   CHIMERA_BRANCH — ветка (авто: main для forgejo/github, chimera-v5 для gitlab/кастома)
# Цепочка fallback: forgejo→gitlab→github (по умолчанию); gitlab→forgejo→github;
#   github→forgejo→gitlab; кастом→forgejo→gitlab→github.

# Настройка переменных ОДНОГО источника: SRC_LABEL / BRANCH / REPO_URL /
# ARCHIVE_URL / SHA256_URL (последние две пустые для кастомного зеркала).
_src_setup() {
    local src="$1"
    if [[ "$src" == "gitlab" ]]; then
        SRC_LABEL="gitlab"
        BRANCH="${CHIMERA_BRANCH:-chimera-v5}"
        REPO_URL="https://gitlab.com/netwalker071778/chimera-project"
        # GitLab-style archive URL (НЕ GitHub-style /archive/refs/heads/,
        # который GitLab перенаправляет на /users/sign_in — требует логина).
        # GitLab-style: /-/archive/{branch}/{project}-{branch}.tar.gz — работает анонимно.
        ARCHIVE_URL="https://gitlab.com/netwalker071778/chimera-project/-/archive/${BRANCH}/chimera-project-${BRANCH}.tar.gz"
        SHA256_URL="https://gitlab.com/netwalker071778/chimera-project/-/raw/${BRANCH}/bootstrap.sh.sha256"
    elif [[ "$src" == "github" ]]; then
        SRC_LABEL="github"
        BRANCH="${CHIMERA_BRANCH:-main}"
        REPO_URL="https://github.com/inferno1978/Chimera-Project.git"
        ARCHIVE_URL="https://github.com/inferno1978/Chimera-Project/archive/refs/heads/${BRANCH}.tar.gz"
        SHA256_URL="https://raw.githubusercontent.com/inferno1978/Chimera-Project/${BRANCH}/bootstrap.sh.sha256"
    elif [[ "$src" == "forgejo" ]]; then
        SRC_LABEL="forgejo"
        BRANCH="${CHIMERA_BRANCH:-main}"
        REPO_URL="https://git.chimeraprodvpn.online/inferno1978/chimera.git"
        # Forgejo-style archive: /archive/{branch}.tar.gz; корневая папка архива —
        # «chimera/» (имя репозитория, без суффикса ветки — см. поиск _extracted).
        ARCHIVE_URL="https://git.chimeraprodvpn.online/inferno1978/chimera/archive/${BRANCH}.tar.gz"
        SHA256_URL="https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/${BRANCH}/bootstrap.sh.sha256"
    else
        # Кастомное зеркало: только git clone — tar.gz и bootstrap.sh.sha256
        # кастомный хост может не отдавать (обе переменные пустые).
        SRC_LABEL="custom"
        BRANCH="${CHIMERA_BRANCH:-chimera-v5}"
        REPO_URL="$src"
        ARCHIVE_URL=""
        SHA256_URL=""
    fi
}

# Цепочка источников: основной (CHIMERA_MIRROR) первым, затем резервные зеркала.
_build_source_chain() {
    local mirror="${CHIMERA_MIRROR:-forgejo}"
    if [[ -z "$mirror" ]]; then
        mirror="forgejo"
    fi
    if [[ "$mirror" != "gitlab" && "$mirror" != "github" && "$mirror" != "forgejo" ]]; then
        if [[ "$mirror" != *"://"* && "$mirror" != "git@"* ]]; then
            warn "CHIMERA_MIRROR='${mirror}' не похож на URL зеркала — использую forgejo."
            mirror="forgejo"
        fi
    fi
    if [[ "$mirror" == "forgejo" ]]; then
        SOURCE_CHAIN=("forgejo" "gitlab" "github")
    elif [[ "$mirror" == "gitlab" ]]; then
        SOURCE_CHAIN=("gitlab" "forgejo" "github")
    elif [[ "$mirror" == "github" ]]; then
        SOURCE_CHAIN=("github" "forgejo" "gitlab")
    else
        SOURCE_CHAIN=("$mirror" "forgejo" "gitlab" "github")
    fi
}

# Проверка целостности: bootstrap.sh из распакованного репозитория сверяется с
# опубликованным bootstrap.sh.sha256 источника (raw-URL). Кастомное зеркало
# (SHA256_URL пуст) или недоступный файл чексуммы → WARN и пропуск (не блокируем).
# Возврат: 0 = OK/пропущено; 1 = РАСХОЖДЕНИЕ (архив битый — пробуем следующее зеркало).
_verify_bootstrap_integrity() {
    local extracted="$1"
    if [[ -z "${SHA256_URL:-}" ]]; then
        warn "Кастомное зеркало: bootstrap.sh.sha256 не используется — проверка целостности пропущена."
        return 0
    fi
    local _expected=""
    _expected=$(curl -fsSL --connect-timeout 15 --retry 2 "${SHA256_URL}" 2>/dev/null | awk '{print $1}') || _expected=""
    if [[ ! "$_expected" =~ ^[0-9a-f]{64}$ ]]; then
        warn "Не удалось получить bootstrap.sh.sha256 (${SRC_LABEL}) — проверка целостности пропущена."
        return 0
    fi
    local _actual=""
    _actual=$(sha256sum "${extracted}/bootstrap.sh" 2>/dev/null | awk '{print $1}') || _actual=""
    if [[ -n "$_actual" && "$_actual" == "$_expected" ]]; then
        ok "Целостность проверена: bootstrap.sh = bootstrap.sh.sha256 (${SRC_LABEL})"
        return 0
    fi
    warn "РАСХОЖДЕНИЕ целостности: bootstrap.sh из архива ≠ bootstrap.sh.sha256 источника (${SRC_LABEL})."
    return 1
}
# <<< CHIMERA MIRRORS

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
        warn "Не удалось скачать архив (${SRC_LABEL}). Проверьте соединение."
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
    for _d in "${_staging}/chimera-project-${BRANCH}" "${_staging}/Chimera-Project-${BRANCH}" "${_staging}/chimera" "${_staging}/VLESS-Ultimate-Installer-${BRANCH}"; do
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

    # --- Stage 3.5: Integrity check (bootstrap.sh ↔ bootstrap.sh.sha256 источника) ---
    if ! _verify_bootstrap_integrity "$_extracted"; then
        warn "Установка НЕ изменена. Пробую следующее зеркало..."
        rm -rf "$_staging" "$_archive_tmp"
        return 1
    fi

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
#  Основная логика обновления / установки (мульти-источник, autofallback)
# =============================================================================
# Один источник (переменные уже настроены через _src_setup). Пробуем штатный
# путь (git pull origin / git clone), при сбое — archive-tarball (если источник
# его отдаёт). Возврат: 0 — успех; 1 — источник не сработал (пробуем следующее).
_acquire_one() {
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        # Git-установка: сначала штатный git pull origin, затем прямой pull
        # с зеркала, затем полный archive-tarball через _archive_update (atomic, с rollback).
        info "Обновление существующей git-установки (${SRC_LABEL})..."
        if git -C "$INSTALL_DIR" pull --quiet origin "$BRANCH" 2>/dev/null; then
            ok "Обновлено до последней версии (fast-forward, origin)"
            return 0
        fi
        info "git pull origin не удался — пробую напрямую ${REPO_URL} (${BRANCH})..."
        if git -C "$INSTALL_DIR" pull --quiet "$REPO_URL" "$BRANCH" 2>/dev/null; then
            ok "Обновлено напрямую с ${SRC_LABEL} (fast-forward)"
            return 0
        fi
        warn "git pull (${SRC_LABEL}) не удался (возможно divergent branches) — полное обновление через archive..."
        if [[ -z "$ARCHIVE_URL" ]]; then
            warn "Кастомное зеркало (${SRC_LABEL}) не отдаёт tar.gz — archive-обновление недоступно."
            return 1
        fi
        # _archive_update может вернуть 1 (graceful failure) — не дадим set -e убить скрипт
        if ! _archive_update "$INSTALL_DIR" "${ARCHIVE_URL}"; then
            return 1
        fi
        return 0
    fi

    if [[ -d "$INSTALL_DIR" ]] && [[ -f "${INSTALL_DIR}/main.py" ]]; then
        # Установка без .git — обновляем через _archive_update (atomic, с rollback)
        info "Установка без git обнаружена — полное обновление через archive (${SRC_LABEL})..."
        if [[ -z "$ARCHIVE_URL" ]]; then
            warn "Кастомное зеркало (${SRC_LABEL}) не отдаёт tar.gz — archive-обновление недоступно."
            return 1
        fi
        if ! _archive_update "$INSTALL_DIR" "${ARCHIVE_URL}"; then
            return 1
        fi
        return 0
    fi

    # Свежая установка: git clone → tar.gz fallback (кастомное зеркало — только clone)
    info "Клонирование репозитория (${SRC_LABEL})..."
    if git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
        ok "Загружено в ${INSTALL_DIR} (${SRC_LABEL}, git clone)"
        return 0
    fi
    warn "git clone (${SRC_LABEL}) не удался — загружаю архив..."
    if [[ -z "$ARCHIVE_URL" ]]; then
        warn "Кастомное зеркало (${SRC_LABEL}) может не отдавать tar.gz — только git clone."
        return 1
    fi
    mkdir -p "$INSTALL_DIR"
    _ARCHIVE_URL="${ARCHIVE_URL}"
    # Для свежей установки используем упрощённый путь (backup не нужен —
    # INSTALL_DIR пустой, откатываться некуда). Но staging + verify — обязательно.
    _CLONE_TMP="/tmp/chimera_install_$$.tar.gz"
    _CLONE_STAGING="/tmp/chimera_clone_staging_$$"
    rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
    if curl -fsSL --connect-timeout 30 --retry 3 -o "$_CLONE_TMP" "$_ARCHIVE_URL" 2>/dev/null; then
        mkdir -p "$_CLONE_STAGING"
        if tar -xzf "$_CLONE_TMP" -C "$_CLONE_STAGING" 2>/dev/null; then
            _extracted=""
            for _d in "${_CLONE_STAGING}/chimera-project-${BRANCH}" "${_CLONE_STAGING}/Chimera-Project-${BRANCH}" "${_CLONE_STAGING}/chimera" "${_CLONE_STAGING}/VLESS-Ultimate-Installer-${BRANCH}"; do
                if [[ -d "$_d" ]]; then _extracted="$_d"; break; fi
            done
            if [[ -n "$_extracted" ]] && [[ -f "${_extracted}/main.py" ]]; then
                # Integrity: bootstrap.sh из архива ↔ bootstrap.sh.sha256 источника
                if ! _verify_bootstrap_integrity "$_extracted"; then
                    warn "Архив (${SRC_LABEL}) не прошёл проверку целостности — пробую следующее зеркало..."
                    rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
                    return 1
                fi
                cp -r "${_extracted}/." "$INSTALL_DIR/"
                ok "Загружено в ${INSTALL_DIR} (${SRC_LABEL}, archive)"
            else
                warn "Архив скачан (${SRC_LABEL}), но директория или main.py не найдены."
                rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
                return 1
            fi
        else
            warn "Не удалось распаковать архив (${SRC_LABEL})."
            rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
            return 1
        fi
        rm -rf "$_CLONE_STAGING" "$_CLONE_TMP"
        return 0
    else
        warn "Не удалось загрузить архив (${SRC_LABEL}). Проверьте соединение."
        rm -f "$_CLONE_TMP"
        return 1
    fi
}

# Основной цикл: источники по цепочке, каждый сбой (timeout/ошибка/битый архив)
# → следующее зеркало. Каждая попытка логируется.
_build_source_chain
_ACQUIRE_OK=0
_src_total=${#SOURCE_CHAIN[@]}
_src_i=0
for _src in "${SOURCE_CHAIN[@]}"; do
    _src_i=$((_src_i + 1))
    _src_setup "$_src"
    info "Источник ${_src_i}/${_src_total}: ${SRC_LABEL} — ${REPO_URL} (ветка ${BRANCH})"
    if _acquire_one; then
        _ACQUIRE_OK=1
        break
    fi
    if [[ "$_src_i" -lt "$_src_total" ]]; then
        warn "Источник «${SRC_LABEL}» не сработал — перехожу к следующему зеркалу..."
    fi
done

if [[ "$_ACQUIRE_OK" != "1" ]]; then
    if [[ -f "${INSTALL_DIR}/main.py" ]]; then
        # Существующая установка не обновлена, но работоспособна — запускаем как есть
        warn "Все источники не сработали — обновление НЕ выполнено, установка НЕ изменена."
        warn "Запускаю установщик с текущей (существующей) версией."
        warn "Попробуйте позже вручную: cd ${INSTALL_DIR} && git reset --hard origin/${BRANCH}"
    else
        err "Не удалось загрузить Chimera Project ни с одного источника (forgejo/gitlab/github)."
        err "Проверьте соединение или укажите зеркало:"
        err "  CHIMERA_MIRROR=<mirror-url> bash bootstrap.sh"
        exit 1
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
