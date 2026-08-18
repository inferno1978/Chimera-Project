# DPI Bypass (b4) — FAQ по обходу ТСПУ для YouTube и любых заблокированных ресурсов

Полное руководство по DPI Bypass через b4 (Bye Bye Big Bro) — интеграция в
Chimera Project. Охватывает YouTube (специализированный модуль) и централизованный
модуль для любых ресурсов.

> **b4** — Linux-демон (Go, статически слинкованный), перехватывает исходящий
> TCP/UDP трафик через NFQUEUE и применяет DPI-обход: фейковый SNI, фрагментацию
> ClientHello, fake RST. ТСПУ не может сопоставить SNI → пропускает трафик.
> Репозиторий: https://github.com/DanielLavrushin/b4

---

## Оглавление

1. [Что такое DPI Bypass и зачем он нужен](#1-что-такое-dpi-bypass-и-зачем-он-нужен)
2. [Архитектура: как b4 работает в Chimera](#2-архитектура-как-b4-работает-в-chimera)
3. [DPI Bypass для YouTube — полный путь из главного меню](#3-dpi-bypass-для-youtube--полный-путь-из-главного-меню)
4. [Централизованный DPI Bypass — полный путь из главного меню](#4-централизованный-dpi-bypass--полный-путь-из-главного-меню)
5. [Установка b4](#5-установка-b4)
6. [Переключение пресетов (default / aggressive / light)](#6-переключение-пресетов-default--aggressive--light)
7. [Импорт кастомных сетов из Discovery](#7-импорт-кастомных-сетов-из-discovery)
8. [Discovery — автоподбор рабочего сета](#8-discovery--автоподбор-рабочего-сета)
9. [Автообновление b4](#9-автообновление-b4)
10. [Health check — проверка работоспособности](#10-health-check--проверка-работоспособности)
11. [Web UI b4 и nginx front (прямой доступ по HTTPS)](#11-web-ui-b4-и-nginx-front-прямой-доступ-по-https)
12. [Управление set'ами (CRUD)](#12-управление-setами-crud)
13. [Синхронизация между YouTube b4 и централизованным DPI Bypass](#13-синхронизация-между-youtube-b4-и-централизованным-dpi-bypass)
14. [Удаление b4](#14-удаление-b4)
15. [Решение проблем](#15-решение-проблем)

---

## 1. Что такое DPI Bypass и зачем он нужен

**ТСПУ** (Технические средства противодействия угрозам) — DPI-система
на уровне российских провайдеров. Она:

- Видит SNI в TLS ClientHello → блокирует/троттлит соединения к
  заблокированным доменам (например, `youtube.com`).
- Блокирует QUIC (UDP/443) — браузер не может установить соединение.
- Отвечает forged RST — рвёт соединение.

**b4** обходит ТСПУ:

1. **Фейковый SNI** — отправляет decoy ClientHello с SNI другого сайта
   (например, `staticcdn.duckduckgo.com` или `www.google.com`). ТСПУ читает
   фейк и думает, что соединение к разрешённому сайту. Реальный сервер
   отбрасывает фейк (по TTL или TCP-seq).
2. **Фрагментация ClientHello** — разбивает реальный ClientHello на 3-4
   TCP-сегмента с паузами 20-60ms. ТСПУ не может собрать полный SNI.
3. **QUIC-перехват** — b4 перехватывает UDP/443 (QUIC) и применяет
   тот же DPI-обход.
4. **Fake RST** — инжектит фейковые RST/FIN с плохими checksums для
   corrupt DPI per-flow state.

**Результат:** ТСПУ не может сопоставить SNI → пропускает → YouTube работает.

---

## 2. Архитектура: как b4 работает в Chimera

```
Клиент (без изменений)
    ↓ VLESS Reality (ТСПУ не видит — TLS-handshake замаскирован)
Entry VPS (chimeravpn.online)
    ↓ Xray inbound (port 443)
    ↓ Xray routing: geosite:youtube → outbound:direct
    ↓ freedom outbound открывает TCP к youtube.com:443
    ↓ iptables mangle OUTPUT → NFQUEUE 537
    ↓ b4 daemon (Go, systemd):
    ↓   SNI=youtube.com? → DROP + inject fake Google SNI + фрагментация
    ↓   raw socket (SO_MARK=32768) → YouTube CDN
    ↓ ТСПУ не видит SNI → пропускает → YouTube работает
YouTube CDN
```

**Ключевые принципы:**

- b4 ставится **только на entry VPS** (не на exit, не на клиенте).
- b4 перехватывает **исходящий** трафик от Xray к YouTube CDN.
- b4 не требует изменений в конфиге Xray — работает поверх routing
  `geosite:youtube → direct`.
- b4 не конфликтует с UFW/iptables/ingress_geoip (mangle vs filter таблицы).
- b4 работает на L3 — не важно, IPv4 или IPv6.

---

## 3. DPI Bypass для YouTube — полный путь из главного меню

```
python3 main.py
→ Главное меню → 3 (Настройки сети)
→ Меню «Настройки сети» → Y (YouTube через RU)
→ Меню «YouTube маршрутизация» → 1 (YouTube через RU entry)
   (включает geosite:youtube → outbound:direct в Xray)
→ Вернуться назад → B (b4 DPI bypass)
→ Меню b4 → 1 (Установить)
```

После установки b4:
- YouTube-трафик с entry VPS перехватывается b4.
- Применяется fake SNI + фрагментация.
- ТСПУ пропускает → YouTube работает.

**Дополнительно в меню b4:**
- Пункт 2 — переключить preset (default / aggressive / light)
- Пункт 3 — импорт кастомного сета
- Пункт 4 — Discovery (автоподбор)
- Пункт 5 — Health check
- Пункт 6 — Логи
- Пункт 7 — Web UI (SSH-туннель инструкция)
- Пункт 8 — nginx front (прямой доступ к Web UI по HTTPS)
- R — удалить b4

**Альтернативный запуск (без главного меню):**
```bash
python3 -m chimera.modules.youtube_b4
```

---

## 4. Централизованный DPI Bypass — полный путь из главного меню

```
python3 main.py
→ Главное меню → 3 (Настройки сети)
→ Меню «Настройки сети» → D (DPI Bypass)
→ Меню «DPI Bypass (b4) — централизованный»
```

**Что показывает меню:**
- Статус: active/stopped + версия + проверка обновлений
- Список всех set'ов с доменами
- Кнопки управления

**Пункты меню:**
- 1 — Запуск/остановка b4
- 2 — Импорт кастомного сета (JSON) — добавляет к существующим
- 3 — Управление set'ами (включить/выключить/удалить)
- 4 — Проверка обновления b4 (скачивание + SHA256 + замена)
- 5 — Health check (проверка доступности сайтов из всех set'ов)
- 6 — Логи b4 (последние 30 строк journalctl)

**Альтернативный запуск:**
```bash
python3 -m chimera.modules.dpi_bypass
```

---

## 5. Установка b4

**Способ 1 — через YouTube меню:**
```
Главное меню → 3 (Настройки сети) → Y (YouTube) → 1 (RU entry) → B (b4) → 1 (Установить)
```

**Способ 2 — через централизованное меню:**
```
Главное меню → 3 (Настройки сети) → D (DPI Bypass)
```
Если b4 не установлен — будет предложено установить.

**Способ 3 — через CLI:**
```bash
python3 -m chimera.modules.youtube_b4 install
```

**Что происходит при установке:**
1. Скачивается b4 binary с GitHub releases (linux-amd64, ~7MB).
2. Создаётся конфиг `/etc/b4/config.json` с set "Youtube" (22 домена).
3. Создаётся systemd-unit `/etc/systemd/system/b4.service`.
4. Применяются iptables mangle правила:
   - TCP/443 → NFQUEUE 537
   - UDP/53 → NFQUEUE 537 (DNS interception)
   - UDP/443 → NFQUEUE 537 (QUIC перехват)
5. Регистрируются порты в port_registry:
   - 9700 (Web UI, loopback)
   - 5453 (DNS TCP, internal)
6. Сервис запускается и включается в автозагрузку.

---

## 6. Переключение пресетов (default / aggressive / light)

**Путь:**
```
Главное меню → 3 (Настройки сети) → Y (YouTube) → B (b4) → 2 (Переключить preset)
```

**3 пресета:**

| Preset | Fake SNI | seg2delay | Описание |
|---|---|---|---|
| Default | DuckDuckGo (sni_type=3) | 20-60ms | Эталон, проверенный на провайдере |
| Aggressive | Google (sni_type=2) | 10-30ms | Меньше delay, для жёсткого DPI |
| Light | Нет (sni=false) | 30-80ms | Только фрагментация, без fake SNI |

**Если YouTube перестал работать** — переключите на другой preset.
ТСПУ постоянно обновляет правила — то, что работало вчера, может не работать сегодня.

---

## 7. Импорт кастомных сетов из Discovery

**Путь:**
```
Главное меню → 3 (Настройки сети) → D (DPI Bypass) → 2 (Импортировать кастомный сет)
```

Или через YouTube меню:
```
Главное меню → 3 (Настройки сети) → Y (YouTube) → B (b4) → 3 (Импорт кастомного сета)
```

**Как импортировать:**
1. Запустите Discovery в b4 Web UI (через браузер).
2. Discovery подберёт рабочий сет → скопируйте JSON.
3. Вставьте JSON в TUI (многострочный ввод, двойной Enter = конец).

**Формат JSON:**
```json
{
  "name": "Discord",
  "enabled": true,
  "targets": {
    "sni_domains": ["discord.com", "discord.gg", "cdn.discordapp.com"]
  },
  "faking": {"sni_type": 2, "ttl": 4},
  "tcp": {"seg2delay": 15, "seg2delay_max": 40},
  "dns": {"enabled": true, "doh_url": "https://1.1.1.1/dns-query"}
}
```

Или формат `{"sets":[...]}` — импортируются все set'ы из массива.

**Что происходит при импорте:**
- Set **добавляется** к существующим (не заменяет YouTube set!).
- Если set с таким `id` уже есть — перезаписывается.
- `geosite_categories` убирается автоматически (если нет `geosite_path`).
- Если `id` не указан — генерируется автоматически (`custom-{timestamp}`).
- b4 перезапускается с обновлённым конфигом.

---

## 8. Discovery — автоподбор рабочего сета

Discovery — встроенная функция b4, которая перебирает сотни комбинаций
(fake SNI типы, TTL, стратегии фрагментации, delay) и находит рабочую
под текущего провайдера хостера.

**Запуск Discovery:**

**Через Web UI (рекомендуется):**
1. Включите nginx front для Web UI:
   ```
   Главное меню → 3 (Настройки сети) → Y (YouTube) → B (b4) → 8 (nginx front)
   → порт 9743 → Let's Encrypt → ваш домен
   ```
2. Откройте `https://<домен>:9743` в браузере.
3. Перейдите на вкладку Discovery → Start.

**Через TUI:**
```
Главное меню → 3 (Настройки сети) → Y (YouTube) → B (b4) → 4 (Discovery)
```

**После Discovery:**
- Скопируйте найденный рабочий сет (JSON).
- Импортируйте через TUI (пункт 2 или 3).

---

## 9. Автообновление b4

**Путь:**
```
Главное меню → 3 (Настройки сети) → D (DPI Bypass) → 4 (Проверить обновление)
```

**Последовательность обновления:**
1. Проверка последней версии на GitHub API.
2. Сравнение с установленной.
3. Если есть обновление:
   a. Скачивание `b4-linux-amd64.tar.gz`.
   b. Проверка SHA256 (через `.sha256` файл).
   c. Остановка сервиса.
   d. Backup старого binary.
   e. Замена binary.
   f. Запуск сервиса.
   g. Проверка что active (если нет — восстановление из backup).
4. **Конфиг и set'ы не затрагиваются.**

**CLI:**
```bash
python3 -m chimera.modules.dpi_bypass update
```

---

## 10. Health check — проверка работоспособности

**Путь:**
```
Главное меню → 3 (Настройки сети) → D (DPI Bypass) → 5 (Health check)
```

Проверяет доступность сайтов из всех set'ов через `curl` с сервера:
- `youtube.com` → 200 = OK
- `ytimg.com` → 200 = OK
- Любой домен из кастомных set'ов

**OK** = любой HTTP-код (2xx/3xx/4xx) — сервер ответил.
**FAIL** = timeout/connection reset — ТСПУ блокирует.

**CLI:**
```bash
python3 -m chimera.modules.youtube_b4 health
python3 -m chimera.modules.dpi_bypass health
```

---

## 11. Web UI b4 и nginx front (прямой доступ по HTTPS)

b4 имеет встроенный Web UI на порту 9700 (только HTTP, только loopback).

**Доступ через SSH-туннель:**
```bash
ssh -L 9700:127.0.0.1:9700 root@<server>
# В браузере: http://localhost:9700
```

**Доступ через nginx front (прямой HTTPS из браузера):**
```
Главное меню → 3 (Настройки сети) → Y (YouTube) → B (b4) → 8 (nginx front)
→ порт 9743 → Let's Encrypt → ваш домен
```

После: `https://<домен>:9743` — Web UI с LE-сертификатом.

**В Web UI можно:**
- Управлять set'ами (включить/выключить)
- Запустить Discovery (автоподбор сета)
- Смотреть статистику в реальном времени
- Импортировать кастомные сеты

---

## 12. Управление set'ами (CRUD)

**Путь:**
```
Главное меню → 3 (Настройки сети) → D (DPI Bypass) → 3 (Список set'ов)
```

**Доступные операции:**
- **Просмотр** — список всех set'ов с доменами и статусом (enabled/disabled)
- **Включить/выключить** — toggle set on/off (b4 перезапускается)
- **Удалить** — удалить set по id (b4 перезапускается)

**CLI:**
```bash
python3 -m chimera.modules.dpi_bypass sets
```

---

## 13. Синхронизация между YouTube b4 и централизованным DPI Bypass

Оба модуля (`youtube_b4.py` и `dpi_bypass.py`) работают с **одним и тем же**
конфигом `/etc/b4/config.json` и **одним и тем же** сервисом `b4.service`.

**Что это значит:**
- Если вы установили b4 через YouTube меню — централизованное меню покажет
  «Установлен, активен» и предложит только управление (не переустановку).
- Если вы импортировали кастомный сет через централизованное меню — он
  появится и в YouTube меню (тот же конфиг).
- Если вы удалили set через одно меню — он исчезнет и в другом.
- Переключение preset в YouTube меню меняет set "youtube" — централизованное
  меню покажет обновлённый set.

**Двусторонняя синхронизация** — без дополнительного кода, через общий файл.

---

## 14. Удаление b4

**Через YouTube меню:**
```
Главное меню → 3 (Настройки сети) → Y (YouTube) → B (b4) → R (Удалить)
```

**Через централизованное меню:**
Удаление недоступно напрямую — используйте YouTube меню.
Или через CLI:
```bash
python3 -m chimera.modules.youtube_b4 uninstall
```

**Что удаляется:**
- systemd-unit + mask
- iptables mangle правила (b4_mangle chain)
- Binary `/usr/local/bin/b4`
- Config `/etc/b4/`
- nginx front (если был включён)
- port_registry: снимаются 3 порта (9700, 5453, 9743)

**Что сохраняется:**
- Логи `/var/log/b4/` (для диагностики)
- State файлы в `/var/lib/xray-installer/`

---

## 15. Решение проблем

### YouTube показывает «Нет подключения к интернету»

**Причина:** ТСПУ блокирует QUIC (UDP/443), а b4 не перехватывал QUIC.

**Решение:** Обновите Chimera и переустановите b4:
```bash
cd /opt/chimera && git pull
python3 -m chimera.modules.youtube_b4 uninstall
python3 -m chimera.modules.youtube_b4 install
```

Проверьте что есть правило для UDP/443:
```bash
iptables -t mangle -L b4_mangle -n
# Должно быть 3 правила: tcp/443, udp/53, udp/443
```

### YouTube работал, потом перестал

**Причина:** ТСПУ обновил правила.

**Решение:** Переключите preset:
```
Главное меню → 3 → Y → B → 2 (Переключить preset)
→ 2 (Aggressive) или 3 (Light)
```

Если не помогает — запустите Discovery (пункт 4 или через Web UI).

### b4 запускается, но YouTube не работает

**Проверьте:**
1. `geosite:youtube → direct` включён в Xray:
   ```
   Главное меню → 3 → Y → 1 (RU entry)
   ```
2. b4 видит YouTube-трафик:
   ```bash
   journalctl -u b4 -f
   # Откройте YouTube → должны увидеть строки с youtube.com
   ```
3. Health check:
   ```bash
   python3 -m chimera.modules.youtube_b4 health
   ```

### «Unknown key name 'StartLimitIntervalSec'» в логах

Это безобидное предупреждение (устаревший systemd). Уже исправлено в
последних версиях Chimera — обновитесь:
```bash
cd /opt/chimera && git pull
python3 -m chimera.modules.youtube_b4 uninstall
python3 -m chimera.modules.youtube_b4 install
```

### Как добавить DPI bypass для Discord / Instagram / других сайтов

1. Установите b4 (через YouTube меню).
2. Запустите Discovery в Web UI для нужного домена.
3. Скопируйте найденный сет (JSON).
4. Импортируйте через централизованное меню:
   ```
   Главное меню → 3 → D → 2 (Импорт кастомного сета)
   ```
5. Set добавится к существующему YouTube set — оба будут работать одновременно.
