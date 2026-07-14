#!/usr/bin/env bash
# ============================================================
#  Chimera Project v5.0.0 — Bootstrap
#  Multi-Protocol Anti-DPI Installer
#  bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/Chimera-Project/main/bootstrap.sh)
# ============================================================
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
    echo -e "     ${YELLOW}sudo bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/Chimera-Project/main/bootstrap.sh)${NC}"
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
REPO_URL="https://github.com/inferno1978/Chimera-Project"
BRANCH="main"

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
#  Пост-апгрейд проверка: импорт chimera + авто-очистка старой vless_installer/
# =============================================================================
# Вызывается после успешного archive-fallback (когда cp -rf отработал, но
# старая директория vless_installer/ могла остаться, т.к. cp не удаляет файлы,
# отсутствующие в архиве).
#
# Логика:
#   1. Проверяем, что chimera пакет действительно импортируется из INSTALL_DIR
#      (это подтверждает, что обновление полное и рабочее).
#   2. Если импорт прошёл — удаляем старую vless_installer/ если она существует
#      (auto-cleanup, чтобы не путать пользователя неактивными старыми файлами).
#   3. Если импорт НЕ прошёл — НЕ трогаем vless_installer/, чтобы оставить
#      пользователю хоть что-то рабочее для восстановления.
#   4. Дополнительно: удаляем stale __pycache__ из vless_installer/, если
#      vless_installer/ решено оставить (defensive — должно быть пусто, но
#      на всякий случай).
_verify_and_cleanup_old_package() {
    local install_dir="$1"

    # Шаг 1: проверка импорта chimera
    # Используем PYTHONPATH вместо sys.path.insert, чтобы команда была максимально простой
    if PYTHONPATH="${install_dir}" python3 -c "import chimera; print('chimera version:', chimera.__version__)" >/dev/null 2>&1; then
        ok "Импорт chimera проверен — обновление успешно"

        # Шаг 2: авто-очистка старой vless_installer/ (если есть)
        if [[ -d "${install_dir}/vless_installer" ]]; then
            rm -rf "${install_dir}/vless_installer"
            ok "Старая директория vless_installer/ удалена (auto-cleanup после успешного апгрейда)"
        fi

        # Шаг 3: defensive — удаляем stale __pycache__ от старого пакета, если остались
        # (rm -rf vless_installer выше уже должен был их убрать, но если vless_installer/
        # уже была удалена ранее, проверяем корень)
        find "${install_dir}" -maxdepth 3 -type d -name "__pycache__" -path "*/vless_installer/*" -exec rm -rf {} + 2>/dev/null || true
    else
        # Импорт не прошёл — обновление неполное. НЕ трогаем старую vless_installer/.
        warn "Импорт chimera не прошёл — обновление может быть неполным"
        warn "Старая директория vless_installer/ оставлена (для возможного восстановления)"
        warn "Проверьте ${install_dir}/chimera/ вручную или выполните:"
        warn "  cd ${install_dir} && git reset --hard origin/${BRANCH}"
    fi
}

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Обновление существующей git-установки..."
    cd "$INSTALL_DIR"

    # Пробуем обычный git pull. Если упал (divergent branches, нет сети и т.п.) —
    # fallback на полный archive-tarball. _update_module через curl НЕ используем:
    # он обновляет только 4 файла и не создаёт директории (curl -o не делает mkdir),
    # что приводило к багу: main.py обновлялся до v5.0.0, но chimera/ не создавалась
    # → ModuleNotFoundError при запуске.
    # Archive fallback обновляет ВСЕ файлы сразу через tar -xzf + cp -rf.
    if git pull --quiet origin "$BRANCH" 2>/dev/null; then
        ok "Обновлено до последней версии (fast-forward)"
    else
        warn "git pull не удался (возможно divergent branches) — полное обновление через archive..."
        ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
        ARCHIVE_TMP="/tmp/chimera_update.tar.gz"
        # Имя директории внутри архива = <RepoName>-<branch>
        # GitHub отдаёт архив с именем по текущему названию репо (Chimera-Project-main)
        ARCHIVE_DIR="Chimera-Project-${BRANCH}"
        if curl -fsSL --connect-timeout 30 --retry 3 -o "$ARCHIVE_TMP" "$ARCHIVE" 2>/dev/null; then
            tar -xzf "$ARCHIVE_TMP" -C /tmp/ 2>/dev/null
            if [[ -d "/tmp/${ARCHIVE_DIR}" ]]; then
                cp -rf "/tmp/${ARCHIVE_DIR}/." "$INSTALL_DIR/"
                rm -rf "/tmp/${ARCHIVE_DIR}" "$ARCHIVE_TMP"
                ok "Файлы обновлены до последней версии через archive"
                _verify_and_cleanup_old_package "$INSTALL_DIR"
            else
                # Архив мог скачаться, но директория имеет другое имя
                # (например, если GitHub ещё не переименован — будет VLESS-Ultimate-Installer-main)
                _alt_dir="VLESS-Ultimate-Installer-${BRANCH}"
                if [[ -d "/tmp/${_alt_dir}" ]]; then
                    cp -rf "/tmp/${_alt_dir}/." "$INSTALL_DIR/"
                    rm -rf "/tmp/${_alt_dir}" "$ARCHIVE_TMP"
                    ok "Файлы обновлены через archive (legacy dir name)"
                    _verify_and_cleanup_old_package "$INSTALL_DIR"
                else
                    warn "Архив скачан, но директория не найдена. Проверьте /tmp/${ARCHIVE_DIR}"
                    warn "Возможно, репозиторий ещё не переименован на GitHub."
                    warn "Попробуйте вручную: cd ${INSTALL_DIR} && git reset --hard origin/${BRANCH}"
                fi
            fi
        else
            warn "Не удалось скачать архив. Проверьте соединение с GitHub."
            warn "Попробуйте вручную: cd ${INSTALL_DIR} && git reset --hard origin/${BRANCH}"
        fi
    fi
else
    if [[ -d "$INSTALL_DIR" ]] && [[ -f "${INSTALL_DIR}/main.py" ]]; then
        # Установка без .git — принудительно обновляем все файлы через archive
        info "Установка без git обнаружена — полное обновление через archive..."
        ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
        ARCHIVE_TMP="/tmp/chimera_update.tar.gz"
        ARCHIVE_DIR="Chimera-Project-${BRANCH}"
        if curl -fsSL --connect-timeout 30 --retry 3 -o "$ARCHIVE_TMP" "$ARCHIVE" 2>/dev/null; then
            tar -xzf "$ARCHIVE_TMP" -C /tmp/ 2>/dev/null
            if [[ -d "/tmp/${ARCHIVE_DIR}" ]]; then
                cp -rf "/tmp/${ARCHIVE_DIR}/." "$INSTALL_DIR/"
                rm -rf "/tmp/${ARCHIVE_DIR}" "$ARCHIVE_TMP"
                ok "Файлы обновлены до последней версии через archive"
                _verify_and_cleanup_old_package "$INSTALL_DIR"
            else
                _alt_dir="VLESS-Ultimate-Installer-${BRANCH}"
                if [[ -d "/tmp/${_alt_dir}" ]]; then
                    cp -rf "/tmp/${_alt_dir}/." "$INSTALL_DIR/"
                    rm -rf "/tmp/${_alt_dir}" "$ARCHIVE_TMP"
                    ok "Файлы обновлены через archive (legacy dir name)"
                    _verify_and_cleanup_old_package "$INSTALL_DIR"
                else
                    warn "Архив скачан, но директория не найдена. Проверьте /tmp/${ARCHIVE_DIR}"
                fi
            fi
        else
            warn "Не удалось обновить — используем текущую версию"
        fi
    else
        info "Клонирование репозитория..."
        if ! git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
            warn "git clone не удался — загружаю архив..."
            mkdir -p "$INSTALL_DIR"
            ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
            ARCHIVE_TMP="/tmp/chimera_install.tar.gz"
            ARCHIVE_DIR="Chimera-Project-${BRANCH}"
            curl -fsSL --connect-timeout 30 --retry 3 -o "$ARCHIVE_TMP" "$ARCHIVE" 2>/dev/null || {
                # Пробуем legacy-имя архива (если GitHub ещё не переименован)
                _alt_archive_url="https://github.com/inferno1978/VLESS-Ultimate-Installer/archive/refs/heads/${BRANCH}.tar.gz"
                curl -fsSL --connect-timeout 30 --retry 3 -o "$ARCHIVE_TMP" "$_alt_archive_url" 2>/dev/null || {
                    err "Не удалось загрузить архив. Проверьте соединение."
                    exit 1
                }
            }
            tar -xzf "$ARCHIVE_TMP" -C /tmp/
            # Пробуем оба имени директории
            if [[ -d "/tmp/${ARCHIVE_DIR}" ]]; then
                cp -r "/tmp/${ARCHIVE_DIR}/." "$INSTALL_DIR/"
                rm -rf "/tmp/${ARCHIVE_DIR}" "$ARCHIVE_TMP"
            else
                _alt_dir="VLESS-Ultimate-Installer-${BRANCH}"
                cp -r "/tmp/${_alt_dir}/." "$INSTALL_DIR/" 2>/dev/null && rm -rf "/tmp/${_alt_dir}" "$ARCHIVE_TMP" || {
                    err "Архив скачан, но директория не найдена."
                    exit 1
                }
            fi
        fi
        ok "Загружено в ${INSTALL_DIR}"
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
