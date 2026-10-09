# Инструкция по установке — Chimera Project v5.0.0

## Быстрый старт (рекомендуется)

```bash
# >>> CHIMERA SECURE INSTALL (канонический блок; проверяется tests/test_secure_bootstrap.py)
# Никакой bootstrap не исполняется до успешной проверки подписи Ed25519.
chimera_install() (
    set -euo pipefail
    CHIMERA_PUBKEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+6KSAskfo+LBzW/io8q376wAULspfGTik674H1o8Gu4=
-----END PUBLIC KEY-----'
    CHIMERA_MIRRORS=(
        "https://git.chimeraprodvpn.online/inferno1978/chimera/raw/branch/main/bootstrap.sh"
        "https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh"
        "https://raw.githubusercontent.com/inferno1978/Chimera-Project/main/bootstrap.sh"
    )
    MAX_SIZE=524288  # 512 KiB — разумный потолок размера bootstrap

    command -v openssl >/dev/null 2>&1 || {
        echo "ОШИБКА: не найден openssl — проверка подписи невозможна, установка прервана (см. docs/faq/BOOTSTRAP_SECURITY.md)." >&2
        exit 1
    }
    tmp="$(mktemp /tmp/chimera-bootstrap.XXXXXXXX)"
    sig="${tmp}.sig"
    pub="${tmp}.pub"
    trap 'rm -f "$tmp" "$sig" "$pub"' EXIT
    trap 'rm -f "$tmp" "$sig" "$pub"; exit 130' INT TERM HUP
    printf '%s\n' "$CHIMERA_PUBKEY" > "$pub"
    chmod 600 "$tmp" "$sig" "$pub" 2>/dev/null || true
    openssl pkey -pubin -in "$pub" -noout >/dev/null 2>&1 || {
        echo "ОШИБКА: установленный openssl не поддерживает Ed25519 (требуется OpenSSL >= 1.1.1) — установка прервана." >&2
        exit 1
    }

    n_dl=0; n_bad=0; reasons=""
    for url in "${CHIMERA_MIRRORS[@]}"; do
        rm -f "$tmp" "$sig"
        if ! curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "$tmp" 2>/dev/null; then
            n_dl=$((n_dl+1)); reasons="${reasons}
  - недоступно (сеть/HTTP): ${url}"
            continue
        fi
        size="$(wc -c < "$tmp")"
        if [ "$size" -eq 0 ] || [ "$size" -gt "$MAX_SIZE" ]; then
            n_bad=$((n_bad+1)); reasons="${reasons}
  - подозрительный размер файла (${size} байт): ${url}"
            continue
        fi
        if ! curl -fsSL --connect-timeout 10 --max-time 30 "${url}.sig" -o "$sig" 2>/dev/null; then
            n_bad=$((n_bad+1)); reasons="${reasons}
  - не удалось скачать подпись: ${url}.sig"
            continue
        fi
        if [ "$(wc -c < "$sig")" -ne 64 ]; then
            n_bad=$((n_bad+1)); reasons="${reasons}
  - повреждённая подпись (не 64 байта): ${url}"
            continue
        fi
        if openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$tmp" -sigfile "$sig" >/dev/null 2>&1; then
            rc=0
            bash "$tmp" "$@" || rc=$?
            exit "$rc"
        fi
        n_bad=$((n_bad+1)); reasons="${reasons}
  - ПОДПИСЬ НЕ ПРОШЛА: ${url}"
    done
    if [ "$n_dl" -eq "${#CHIMERA_MIRRORS[@]}" ]; then
        echo "ОШИБКА: не удалось скачать bootstrap ни с одного зеркала (forgejo/gitlab/github). Проверьте сеть и повторите." >&2
    else
        echo "ОШИБКА: проверенный bootstrap получить не удалось — исполнение запрещено (скачанные файлы не прошли проверку подлинности)." >&2
    fi
    echo "Причины:${reasons}" >&2
    exit 1
)
chimera_install "$@"
_chimera_install_rc=$?
unset -f chimera_install 2>/dev/null || true
# Код возврата блока = коду возврата bootstrap (paste-safe: без exit из шелла пользователя)
( exit "$_chimera_install_rc" )
# <<< CHIMERA SECURE INSTALL
```

Bootstrap скрипт автоматически:
1. Проверяет права root
2. Устанавливает `python3`, `curl`, `git` если отсутствуют
3. Клонирует репозиторий в `/opt/chimera`
4. Запускает установщик

---

## Ручная установка

```bash
# 1. Клонировать репозиторий
git clone -b main https://git.chimeraprodvpn.online/inferno1978/chimera.git /opt/chimera
# или с зеркал: -b chimera-v5 https://gitlab.com/netwalker071778/chimera-project.git
cd /opt/chimera

# 2. Проверить целостность
python3 verify.py

# 3. Запустить
sudo python3 main.py
```

---

## Требования

| Параметр | Значение |
|----------|----------|
| ОС | Ubuntu 20.04 / 22.04 / 24.04 LTS, Debian 11 / 12 / 13 |
| Python | 3.10+ (рекомендуется 3.12) |
| RAM | минимум 512 МБ |
| Диск | минимум 2 ГБ |
| Права | root |
| Сеть | публичный IP, домен с A-записью |

### Предустановка Python 3.12 (если нужно)

```bash
# Ubuntu 20.04 / 22.04
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.12

# Ubuntu 24.04 / Debian 12+
sudo apt-get install -y python3
```

---

## Режимы установки

### Режим A — Одиночный сервер

Клиент → Ваш сервер → Интернет

Выбор протокола при установке:
- **VLESS + TCP + REALITY** — максимальная скорость, имитирует TLS 1.3
- **VLESS + xHTTP + TLS** — для сред с жёстким DPI

### Режим B — Каскад (Россия → Зарубеж)

Клиент → RU-сервер → Зарубежный сервер → Интернет

Нужно два VPS: один в России, один за рубежом. SSH-доступ к зарубежному серверу — для автонастройки.

### Мульти-каскад

До 10 зарубежных нод с балансировкой (`roundRobin`, `leastPing`, `pinned`).

---

## После установки

```bash
# Проверить статус сервисов
systemctl status xray nginx

# Посмотреть сгенерированные ссылки
sudo python3 /opt/chimera/main.py
# → Управление пользователями → Показать ссылки

# Лог установки
tail -50 /var/log/chimera.log
```

---

## Обновление

### Из TUI (рекомендуется)

```
sudo python3 main.py
# → Главное меню → 1 Установка и Система → U Обновить Chimera
#   проверка origin → список новых коммитов → git pull --ff-only → перезапуск TUI
```

Там же (U → 2): ночное автообновление в 04:30 (только fast-forward,
лог /var/log/chimera-update.log); U → 3 — вкл/выкл фоновую проверку при
старте (строка «⬆️ Доступно обновление» в главном меню).

### Вручную

```bash
cd /opt/chimera
git pull
sudo python3 main.py
# → Установка и Система → Обновить Xray
```

---

## Удаление

```bash
# Через меню
sudo python3 /opt/chimera/main.py
# → Управление пользователями → Полное удаление

# Или вручную
systemctl stop xray nginx
systemctl disable xray nginx
apt-get remove --purge nginx certbot
rm -rf /etc/xray /var/lib/xray-installer /opt/chimera
```

---

## Проблемы при установке?

Смотри [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
