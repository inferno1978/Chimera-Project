# Telegram-боты Chimera — FAQ по всем трём функциям

Это подробный гайд по трём Telegram-функциям Chimera: admin-боту,
client-боту и cron-уведомлениям. Описано: зачем их три, как каждый
работает, как инициализировать с нуля, все доступные команды,
архитектура, типовые проблемы и их решения, plus большой раздел
вопрос-ответ с точки зрения пользователя.

> **Краткая навигация:**
> - **Admin-бот** (`@Chimeravpnproject_bot`) — интерактивный бот для
>   админа: 25+ команд для управления сервером из Telegram. Запущен
>   только на primary-сервере (cascade_peers режим).
> - **Client-бот** (`@ChimeraVPNClient_bot`) — self-service бот для
>   пользователей VPN: получают свои ссылки/QR без обращения к админу.
>   Запущен на всех серверах (отдельный токен, нет конкуренции).
> - **Cron-уведомления** — push-сообщения от сервера админу при
>   событиях: xray упал, сертификат истекает, autoban сработал, и т.д.
>   Работают на всех серверах (не long-polling, а send-only).

---

## Оглавление

1. [Зачем три разных TG-функции](#1-зачем-три-разных-tg-функции)
2. [Архитектура: почему admin-бот только на одном сервере](#2-архитектура-почему-admin-бот-только-на-одном-сервере)
3. [Инициализация с нуля — пошаговая](#3-инициализация-с-нуля--пошаговая)
4. [Admin-бот — все команды](#4-admin-бот--все-команды)
5. [Client-бот — все команды](#5-client-бот--все-команды)
6. [Cron-уведомления — все события](#6-cron-уведомления--все-события)
7. [Inline-клавиатура /menu — как пользоваться кнопками](#7-inline-клавиатура-menu--как-пользоваться-кнопками)
8. [Архитектура cascade_peers — multi-server /status](#8-архитектура-cascade_peers--multi-server-status)
9. [Безопасность: что можно и нельзя делать из Telegram](#9-безопасность-что-можно-и-нельзя-делать-из-telegram)
10. [Файлы на сервере (полный список)](#10-файлы-на-сервере-полный-список)
11. [Вопрос-ответ](#11-вопрос-ответ)
12. [Типовые проблемы и решения](#12-типовые-проблемы-и-решения)
13. [Шпаргалка по командам](#13-шпаргалка-по-командам)

---

## 1. Зачем три разных TG-функции

Архитектурно это **три независимых подсистемы**, каждая со своей задачей:

| Подсистема | Режим | Где работает | Задача |
|---|---|---|---|
| **Admin-бот** | Long-polling интерактив | Primary-сервер (один) | Приём команд от админа (`/status`, `/ban`, `/restart`) |
| **Client-бот** | Long-polling интерактив | Все серверы (отдельный токен) | Self-service для пользователей (получить конфиг/QR) |
| **Cron-уведомления** | Push-only (без long-polling) | Все серверы | Уведомления при событиях (xray упал, autoban сработал) |

### Почему не один бот на всё

**Безопасность.** Если бы admin-бот и client-бот были одним токеном,
утечка client-бота (который используется десятками/сотнями людей)
дала бы злоумышленнику доступ к admin-командам (`/ban`, `/restart`,
`/users`, `/broadcast`). Раздельные токены = раздельная ответственность:
даже если client-бот токен утёк — злоумышленник получит только
`/config`, `/qr`, `/status` (READ-ONLY), не причинив вреда.

**Доступность.** Long-polling admin-бота — это цикл `getUpdates` к
Telegram API. Только один бот с одним токеном может быть активным
long-poller одновременно (Telegram отдаёт каждое сообщение только
первому успевшему). Если бы admin-бот был на всех 3 серверах —
конкуренция за updates, случайный сервер отвечал бы на `/status`.

Client-бот имеет отдельный токен — его можно запускать на всех
серверах, конкуренции нет (свой токен = своя очередь updates).

**Cron-уведомления не конкурируют.** Они работают через `sendMessage`
Telegram API — односторонняя отправка. Их можно запускать на всех
серверах одновременно, и сообщения будут приходить с каждого сервера
независимо (с пометкой hostname+IP в заголовке).

---

## 2. Архитектура: почему admin-бот только на одном сервере

**Telegram Bot API long-polling** — один токен = один активный
long-poller. Если несколько инстансов бота с одним токеном поллят
`getUpdates` одновременно — Telegram отдаёт каждое сообщение только
первому успевшему. Остальные получают пустой ответ.

**Решение:** admin-бот запускается **только на primary-сервере**
(server 1). На остальных (server 2, server 3) admin-бот остановлен
через `systemctl stop xray-tg-bot && systemctl disable xray-tg-bot`.

**Как тогда получить /status со всех 3 серверов?**

Primary-бот имеет опциональное поле `cascade_peers` в `tg_bot.json` —
список удалённых серверов с SSH-доступом. При `/status` бот через SSH
вызывает `/usr/local/bin/chimera-remote-status.py` на каждом peer и
агрегирует результат в одну сводку:

```
📊 Статус каскада (24.09.2026 11:09)

• Server 1 (inferno1978) (inferno1978) — <server1-ip>
   🟢 Xray=active | REALITY:443 | М=B | Апт: up 6 days, 11 hours, 22 minutes
• Server 2 (vds13195) (vds13195) — <server2-ip>
   🟢 Xray=active | REALITY:9443 | М=B | Апт: up 3 days, 1 hour, 37 minutes
• Server 3 (bright-lynx) (bright-lynx) — <server3-ip>
   🟢 Xray=active | REALITY:443 | М=B | Апт: up 3 weeks, 4 days, 13 hours, 37 minutes
```

**Зависимости для cascade_peers:**
1. Passwordless SSH-ключ на primary к каждому peer (`/root/.ssh/id_ed25519`
   → добавлен в `authorized_keys` на peer)
2. Скрипт `/usr/local/bin/chimera-remote-status.py` на каждом peer
   (standalone Python, возвращает JSON со статусом)
3. Для non-root SSH user (например `inferno1978@server3`) — `sudo: true`
   в peer-конфиге, чтобы вызывать скрипт через `sudo -n`

---

## 3. Инициализация с нуля — пошаговая

### Шаг 1: Создать двух ботов в @BotFather

```
1. Открыть в Telegram @BotFather
2. /newbot
   - Имя: "Chimeravpnproject bot"
   - Username: <домен3>project_bot
   - Получить ADMIN_TOKEN (вида 8866274071:AA...)
3. /newbot (снова)
   - Имя: "ChimeraVPN Client bot"
   - Username: chimera_vpn_client_bot (или любой свободный)
   - Получить CLIENT_TOKEN (вида 8859136245:AA...)
```

**Два токена обязательно** — раздельная ответственность (см. §1).

### Шаг 2: Сделать /start обоим ботам

Открой каждого бота в Telegram и нажми **Start** (или отправь `/start`).
Без этого Telegram API `getUpdates` вернёт пустой список — бот не
сможет узнать твой `chat_id` для отправки уведомлений.

Проверить что Chat ID получен:
```bash
ADMIN_TOKEN='8866274071:AA...'
curl -sS "https://api.telegram.org/bot${ADMIN_TOKEN}/getUpdates" | python3 -m json.tool
# В response.result[0].message.chat.id — твой chat_id (число, например 5003383973)
```

### Шаг 3: Включить всё через chimera TUI

Подключись к primary-серверу по SSH и запусти chimera:
```bash
ssh root@<server1-ip>
cd /opt/chimera && python3 -m chimera
```

В главном меню:
- `[5]` → Telegram-уведомления → `[1]` ввести ADMIN_TOKEN + Chat ID
  → `[4]` установить cron-мониторинг
- `[TB]` → Admin-бот → `[1]` ввести ADMIN_TOKEN + admin_id (= Chat ID)
  → `[2]` запустить бота
- `[TC]` → Client-бот → `[1]` ввести CLIENT_TOKEN + admin_id
  → `[2]` запустить бота

Для cascade_peers — вручную отредактировать `/var/lib/xray-installer/tg_bot.json`:
```json
{
  "token": "8866274071:AA...",
  "admin_id": "5003383973",
  "allowed_users": [5003383973],
  "invite_tokens": {},
  "local_name": "Server 1 (inferno1978)",
  "local_ip": "<server1-ip>",
  "cascade_peers": [
    {"host": "<server2-ip>", "user": "root", "port": 22, "name": "Server 2 (vds13195)", "sudo": false},
    {"host": "<server3-ip>", "user": "inferno1978", "port": 22, "name": "Server 3 (bright-lynx)", "sudo": true}
  ]
}
```

После правки — регенерировать inner-скрипт:
```bash
python3 -c "
import sys; sys.path.insert(0, '/opt/chimera')
from chimera.modules.tg_bot import _bot_load, _install_bot_service
_install_bot_service(_bot_load())
"
```

### Шаг 4: Для cascade_peers — настроить SSH-связки

На primary-сервере:
```bash
# Сгенерировать SSH-ключ (если ещё нет)
ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519

# Добавить public key на каждый peer
ssh-copy-id root@<server2-ip>
ssh-copy-id inferno1978@<server3-ip>

# ИЛИ вручную: cat /root/.ssh/id_ed25519.pub → добавить в peer's
# /root/.ssh/authorized_keys (или /home/inferno1978/.ssh/authorized_keys)
```

Также установить `/usr/local/bin/chimera-remote-status.py` на каждый peer
(chimera деплоит его автоматически при установке, см. scripts/chimera-remote-status.py).

### Шаг 5: Добавить server_ip в telegram.json (для IP в уведомлениях)

На **каждом** сервере отредактировать `/var/lib/xray-installer/telegram.json`:
```json
{
  "token": "8866274071:AA...",
  "chat_id": "5003383973",
  "server_ip": "<server1-ip>",
  "events": {
    "xray_down": true, "xray_up": true, "cert_expire": true,
    "traffic_limit": true, "health_report": true,
    "node_down": true, "port_blocked": true, "autoban": true
  }
}
```

После правки — регенерировать cron-скрипт:
```bash
python3 -c "
import sys; sys.path.insert(0, '/opt/chimera')
from chimera.modules.tg_bot import tg_load, _install_monitor_cron
_install_monitor_cron()
"
```

### Шаг 6: Остановить admin-бота на secondary-серверах

Только primary-сервер должен держать long-polling admin-бота:
```bash
# На server 2 и server 3
systemctl stop xray-tg-bot
systemctl disable xray-tg-bot
# client-бот и cron-мониторинг ОСТАЮТСЯ активными
```

### Шаг 7: Проверка

В `@Chimeravpnproject_bot`:
- `/status` — должна прийти сводка со всех 3 серверов с IP
- `/menu` — должна прийти inline-клавиатура с кнопками
- `/help` — расширенная справка с 7 категориями

В `@ChimeraVPNClient_bot`:
- `/menu` — 5 кнопок
- `/protocols` — описание протоколов + клиенты по платформам

---

## 4. Admin-бот — все команды

### Базовые
| Команда | Описание |
|---|---|
| `/start` | Приветствие + список популярных команд + текущий сервер |
| `/config` | VLESS-ссылка текущего пользователя |
| `/help` | Расширенная справка по 7 категориям |
| `/menu` | Inline-клавиатура с кнопками для всех команд |

### Статус и мониторинг
| Команда | Описание |
|---|---|
| `/status` | Агрегированный статус каскада со всех серверов (через SSH) |
| `/status_local` | Статус только текущего (primary) сервера |
| `/health` | Запускает chimera diagnostics (11 проверок) |
| `/version` | Версия chimera + git commit + uptime бота + cascade peers count |
| `/cert` | Статус TLS-сертификатов на всех серверах каскада (🟢 >30d, 🔴 <30d, 💀 expired) |

### Пользователи
| Команда | Описание |
|---|---|
| `/users` | Список пользователей Xray (email + UUID short) |
| `/users_active` | Активные пользователи за последние 5000 строк access.log |
| `/user <email>` | Детальная инфа по пользователю (UUID, flow, TTL, лимит) |
| `/reset_user <email>` | Сброс traffic counter (отключено — требует TUI) |
| `/traffic [n]` | Топ-N по подключениям (по умолчанию 10, cap 50) |
| `/traffic_top` | Алиас для `/traffic 20` |
| `/invite` | Создать одноразовую invite-ссылку для нового пользователя |
| `/broadcast <текст>` | Рассылка всем привязанным пользователям |

### Бан-лист и whitelist
| Команда | Описание |
|---|---|
| `/ban <ip>` | Ручной бан IP в xray_manual_ban ipset + сохранение в /etc/ipset.conf |
| `/unban <ip>` | Разбан IP |
| `/banlist` | Список забаненных IP (до 50, с суффиксом «... и ещё N») |
| `/whitelist` | Список whitelist IP (ipset clients_wl) |
| `/wl_add <ip>` | Добавить IP в whitelist (защита от autoban) |
| `/wl_del <ip>` | Удалить IP из whitelist |

### GeoIP и fail2ban
| Команда | Описание |
|---|---|
| `/geo` | Статус ingress GeoIP-блокировки (IPv4 CIDR + IPv6 CIDR + iptables rule) |
| `/geo_toggle` | Переключить (отключено — требует TUI) |
| `/f2b` (алиас `/f2b_status`) | Статус fail2ban-client + топ-5 jails |

### Каскад и ноды
| Команда | Описание |
|---|---|
| `/nodes` | Список exit-нод каскада + TCP-ping до каждой |
| `/probe <ip/host> [port]` | TCP-ping до произвольного адреса (по умолчанию порт 443) |

### Управление сервисами
| Команда | Описание |
|---|---|
| `/restart <service>` | Перезапуск: xray/nginx/dnscrypt/agh/adguardhome/fail2ban/warp |
| `/reload_nginx` | Мягкий reload nginx без обрыва соединений |
| `/logs [service] [n]` | Последние N строк лога. Services: xray, xray_acc, nginx, nginx_acc, chimera, fail2ban, dnscrypt, system |

---

## 5. Client-бот — все команды

| Команда | Описание |
|---|---|
| `/start [token]` | Приветствие + привязка аккаунта (один раз, через invite-токен от админа) |
| `/config` | Список ссылок для всех активных протоколов + inline-кнопки для `/qr` |
| `/qr <протокол>` | QR-код для конкретного протокола (PNG-картинка в чат) |
| `/status` (алиас `/traffic`) | Трафик + прогресс-бар + TTL + лимит |
| `/protocols` | Описание всех доступных протоколов + клиенты по платформам |
| `/guide` | 5-шаговое руководство по подключению |
| `/menu` | Inline-клавиатура с 5 кнопками |
| `/help` | Справка со списком команд |

**READ-ONLY:** client-бот не умеет добавлять/удалять/банить
пользователей — это сделано специально для безопасности.

---

## 6. Cron-уведомления — все события

Cron-скрипт `/usr/local/bin/xray-tg-monitor.sh` запускается каждые 5
минут через `/etc/cron.d/xray-tg-monitor`. Отправляет сообщения через
`curl sendMessage` (не long-polling — конкуренции нет, можно на всех
серверах).

**События из cron-скрипта (bash):**
| Событие | Когда срабатывает | Формат сообщения |
|---|---|---|
| `xray_down` | `systemctl is-active xray` != active (один раз, с `/tmp/xray-tg-down.stamp` для дедупликации) | 🔴 [hostname \| IP] Xray не запущен! |
| `xray_up` | Xray восстановился (если был stamp) | 🟢 [hostname \| IP] Xray восстановился. |
| `cert_expire` | Let's Encrypt сертификат истекает < 30 дней (один раз в день, проверяется каждый запуск) | 🔒 [hostname \| IP] Сертификат истекает через N дн. |

**События из chimera (Python `_tg_notify_event`):**
| Событие | Когда срабатывает | Иконка |
|---|---|---|
| `traffic_limit` | Пользователь превысил traffic-лимит (из traffic_tracking.py) | ⚠️ |
| `user_connect` | Новое подключение пользователя (если включено в events) | 👤 |
| `health_report` | Ежедневный health-отчёт (08:00, cron) | 📋 |
| `node_down` | Exit-нода каскада недоступна (из failover-мониторинга) | 📡 |
| `port_blocked` | Порт заблокирован ТСПУ (из port-hopping-детектора) | 🚫 |
| `autoban` | AutoBan забанил IP автоматически (10+ TLS errors за 60 сек) | 🛡️ |
| `port_hopping` | Сработал port-hopping (сменя порт на новый из пула) | ⚡ |

**Формат сообщений (после v6 фикса):**
```
{icon} [hostname | server_ip] {detail}
{timestamp}
```

Пример:
```
🛡️ [vds13195 | <server2-ip>] IP 8.8.8.8 забанен автоматически
24.09.2026 11:15
```

---

## 7. Inline-клавиатура /menu — как пользоваться кнопками

Когда ты отправляешь `/menu` в `@Chimeravpnproject_bot`, бот присылает
inline-клавиатуру — кнопки прямо в чате. Нажатие на кнопку — это
`callback_query` к боту, и бот выполняет соответствующую команду без
необходимости печатать её текст.

**Admin-бот /menu:**
```
🎛️ Admin menu — выберите команду:

[📊 Статус каскада]
[👥 Пользователи] [🛡️ Бан-лист]
[🔒 Сертификаты] [📋 Версия]
[🌍 Geo-IP] [🛡️ fail2ban]
[🔗 Ноды] [🚦 Трафик]
[🔄 Restart menu]
[❓ Помощь]
```

Каждая кнопка → `callback_data` с именем команды. Бот обрабатывает
`callback_query` через `handle_callback_query(cb)` — создаёт fake_msg
с `from.id` = `cb.from.id`, парсит callback_data как команду, и
диспетчеризует в соответствующий `handle_*`.

**Client-бот /menu:**
```
🎛️ Меню — выберите действие:

[🔗 Получить конфиг]
[📊 Трафик и TTL]
[🔌 Протоколы]
[📘 Руководство]
[❓ Помощь]
```

Кнопки используют `menu:action` формат callback_data (вместо имени
команды). `handle_callback` парсит action и вызывает нужную
handle_* функцию (config/status/protocols/guide/help).

**Преимущества inline-кнопок:**
1. Не нужно запоминать синтаксис команды
2. Не нужно печатать (особенно на мобильном)
3. Команды с аргументами (`/ban <ip>`) показывают usage-hint
4. Видны все доступные команды одним сообщением

---

## 8. Архитектура cascade_peers — multi-server /status

### Принцип

`tg_bot.json` имеет опциональное поле `cascade_peers` — список
удалённых серверов. Если задан, `/status` собирает агрегированную
сводку с primary + всех peer'ов через SSH.

### Конфиг

```json
"cascade_peers": [
  {
    "host": "<server2-ip>",
    "user": "root",
    "port": 22,
    "name": "Server 2 (vds13195)",
    "sudo": false
  },
  {
    "host": "<server3-ip>",
    "user": "inferno1978",
    "port": 22,
    "name": "Server 3 (bright-lynx)",
    "sudo": true
  }
]
```

- `host` — IP удалённого сервера
- `user` — SSH-пользователь (`root` или non-root)
- `port` — SSH-порт (обычно 22)
- `name` — человеко-читаемое имя для вывода в /status
- `sudo` — `true` если SSH-пользователь non-root (нужно `sudo -n` для
  выполнения системных команд)

### SSH-связки

Primary-сервер должен иметь passwordless SSH-ключ к каждому peer:

```bash
# На primary (server 1):
ls -la /root/.ssh/id_ed25519.pub
# Скопировать public key на каждый peer:
# - Для root-peer: добавить в /root/.ssh/authorized_keys
# - Для non-root peer: добавить в /home/<user>/.ssh/authorized_keys

# Тест passwordless SSH:
ssh root@<server2-ip> 'hostname'   # должно вывести vds13195 без пароля
ssh inferno1978@<server3-ip> 'id'    # должно показать uid=1000
```

### Remote status script

На **каждом** сервере должен быть установлен
`/usr/local/bin/chimera-remote-status.py` (chmod 755, owner root).

Этот standalone Python-скрипт:
1. Читает `/var/lib/xray-installer/state.json` (поля protocol_mode,
   server_port, install_mode)
2. Выполняет `systemctl is-active xray` и `hostname -s` и `uptime -p`
3. Возвращает одну JSON-строку:
   ```json
   {"host":"vds13195","xray":"active","proto":"reality","port":9443,"mode":"B","uptime":"up 3 days"}
   ```

Bot-скрипт primary-сервера вызывает:
- `ssh root@peer /usr/local/bin/chimera-remote-status.py` (root peer)
- `ssh user@peer sudo -n /usr/local/bin/chimera-remote-status.py` (non-root peer)

### Что показывает /status с cascade_peers

```
📊 Статус каскада (24.09.2026 11:09)

• Server 1 (inferno1978) (inferno1978) — <server1-ip>
   🟢 Xray=active | REALITY:443 | М=B | Апт: up 6 days, 11 hours, 22 minutes
• Server 2 (vds13195) (vds13195) — <server2-ip>
   🟢 Xray=active | REALITY:9443 | М=B | Апт: up 3 days, 1 hour, 37 minutes
• Server 3 (bright-lynx) (bright-lynx) — <server3-ip>
   🟢 Xray=active | REALITY:443 | М=B | Апт: up 3 weeks, 4 days, 13 hours, 37 minutes
```

Если peer недоступен — вместо статуса:
```
• Server 2 (vds13195) (<server2-ip>): ❌ SSH exit=255: Connection timed out
```

### Команда /status_local

Если хочешь только статус текущего (primary) сервера без SSH-вызовов
к peer'ам — используй `/status_local`. Быстрее, не зависит от SSH.

---

## 9. Безопасность: что можно и нельзя делать из Telegram

### ✅ Можно делать из TG

- `/ban <ip>` — бан IP в `xray_manual_ban` ipset (валидация IPv4 regex)
- `/unban <ip>` — разбан
- `/restart <service>` — но только для whitelist сервисов (xray/nginx/
  dnscrypt/agh/fail2ban/warp). Никаких `shutdown`, `reboot`, `systemctl
  poweroff`.
- `/reload_nginx` — мягкий reload, безопасно
- `/logs [service]` — чтение, не меняет состояние
- `/banlist`, `/whitelist`, `/users`, `/users_active`, `/traffic` —
  только чтение
- `/geo` — только статус (не toggle)
- `/f2b` — только статус
- `/probe` — TCP-ping, не меняет состояние
- `/cert`, `/version`, `/health`, `/status`, `/status_local` — только чтение

### ❌ Нельзя делать из TG (требует chimera TUI)

- `/reset_user <email>` — сброс traffic counter (может повлиять на
  биллинг, требует подтверждения в TUI)
- `/geo_toggle` — переключить ingress GeoIP-блокировку (может вырубить
  весь трафик если выключить, или добавить 11000 CIDR если включить —
  слишком опасно для удалённого выполнения)

Эти команды при вызове из TG просто присылают инструкцию:
«Используйте chimera TUI на сервере: Меню → Управление ...»

### Все admin-команды проверяют is_admin

В начале каждой `handle_*` функции:
```python
def handle_ban(msg, args):
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
```

`is_admin` проверяет что `uid == ADMIN_ID` (из `tg_bot.json`).
Обычные пользователи (даже если знают команду) получают отказ.

### Client-бот READ-ONLY

Client-бот не имеет ни одной команды, которая меняет состояние сервера:
- `/config` — только отдаёт ссылки (из state.json)
- `/qr` — только генерирует QR-код
- `/status` — только показывает трафик/TTL
- `/protocols`, `/guide`, `/menu`, `/help` — статичные сообщения

Даже если токен client-бота утёк — злоумышленник не сможет:
- Забанить/разбанить IP
- Перезапустить сервис
- Удалить пользователя
- Изменить конфиг

Максимум — узнать конфиги пользователей (ссылки vless://, QR-коды).

---

## 10. Файлы на сервере (полный список)

### Admin-бот (только на primary)

| Файл | Назначение |
|---|---|
| `/var/lib/xray-installer/tg_bot.json` | Конфиг admin-бота: token, admin_id, allowed_users, invite_tokens, local_name, local_ip, cascade_peers |
| `/usr/local/bin/xray-tg-bot.py` | Сгенерированный inner-скрипт (long-polling, standalone) |
| `/etc/systemd/system/xray-tg-bot.service` | systemd-unit для сервиса xray-tg-bot |

### Client-бот (на всех серверах)

| Файл | Назначение |
|---|---|
| `/var/lib/xray-installer/tg_client_bot.json` | Конфиг client-бота: token, admin_id, rate_limit_seconds, invite_tokens |
| `/var/lib/xray-installer/tg_client_bot_map.json` | Привязка TG user_id → UUID пользователя Chimera (создаётся при `/start <token>`) |
| `/usr/local/bin/xray-tg-client-bot.py` | Сгенерированный inner-скрипт (long-polling, standalone) |
| `/etc/systemd/system/xray-tg-client.service` | systemd-unit для сервиса xray-tg-client |

### Cron-уведомления (на всех серверах)

| Файл | Назначение |
|---|---|
| `/var/lib/xray-installer/telegram.json` | Конфиг уведомлений: token, chat_id, server_ip, events |
| `/usr/local/bin/xray-tg-monitor.sh` | Bash-скрипт мониторинга (каждые 5 мин) |
| `/etc/cron.d/xray-tg-monitor` | cron-задача (запуск xray-tg-monitor.sh каждые 5 мин) |

### Remote status (на всех серверах, для cascade_peers)

| Файл | Назначение |
|---|---|
| `/usr/local/bin/chimera-remote-status.py` | Standalone Python-скрипт, возвращает JSON со статусом сервера (вызывается primary-ботом через SSH при /status) |

### Логи

| Файл | Назначение |
|---|---|
| `/var/log/chimera.log` | Лог chimera, включая TG-события (`[TG]`, `[BOT]`, `[TG-CLIENT]`) |
| `/var/log/xray/error.log` | Лог Xray — ошибки, REALITY-сканеры, etc. |
| `/var/log/xray/access.log` | Лог Xray — все подключения (для /users_active, /traffic) |

---

## 11. Вопрос-ответ

### Общие вопросы

**В: Зачем три бота, можно ли обойтись одним?**
О: Нельзя, если хочешь, чтобы у каждого пользователя был self-service
доступ (/config, /qr) и при этом admin-команды (/ban, /restart) были
защищены. Один бот = один токен, утечка client-бота дала бы полный
admin-доступ. Два токена = раздельная ответственность.

**В: Можно ли использовать admin-бота как client-бота (без client-бота)?**
О: Технически да — admin-бот умеет `/config` и `/invite`. Но тогда
обычные пользователи получат admin-команды (`/users`, `/ban`, etc.).
Безопасности ради — отдельный client-бот.

**В: Что если я потеряю токен admin-бота?**
О: В @BotFather есть команда `/revoke` — отзывает старый токен и
выдаёт новый. Обнови `tg_bot.json` на primary и `telegram.json` на
всех серверах (токен один и тот же для admin + cron-уведомлений),
регенерируй скрипты. Старый токен перестанет работать мгновенно.

**В: Что если бот перестал отвечать на /status?**
О: Проверь на primary:
```bash
systemctl status xray-tg-bot
journalctl -u xray-tg-bot -n 30 --no-pager
```
Самые частые причины:
1. api.telegram.org недоступен с сервера (блокировка ТСПУ, нет WARP)
2. Токен отозван в BotFather
3. tg_bot.json повреждён (невалидный JSON)
4. SSH-связки к cascade_peers сломались (для /status)

**В: Бот упал, как его перезапустить?**
О: `systemctl restart xray-tg-bot` (admin) или `xray-tg-client` (client).
Systemd-unit имеет `Restart=always` + `RestartSec=10`, так что бот
должен сам перезапускаться. Если падает в loop — проверь логи.

### По admin-боту

**В: Я случайно забанил свой IP через /ban, что делать?**
О: `/unban <твой-ip>` — мгновенно разбанит. Также добавь себя в
whitelist через `/wl_add <твой-ip>` — это защитит от случайного
автобана в будущем (whitelist = ACCEPT правило до DROP).

**В: /restart xray не помогает, бот возвращает «exit=0» но xray всё равно не работает**
О: `exit=0` значит systemctl restart прошёл успешно, но это не значит
что xray запустился. После /restart xray проверь:
- `/status` — должен показать `🟢 Xray=active`
- `/logs xray 50` — последние 50 строк error.log
- `/health` — полная chimera диагностика

Если `🔴 Xray=inactive` —大概率 конфиг сломан, смотри /logs.

**В: /cert показывает «сертификат не найден»**
О: Это значит на сервере нет Let's Encrypt сертификата в
`/etc/letsencrypt/live/*/cert.pem`. Возможно используется self-signed
или сертификат в другом месте. Проверь:
```bash
find /etc/letsencrypt/live -name 'cert.pem' 2>/dev/null
```

**В: /status показывает ❌ для одного peer, что делать?**
О: Проверь SSH-связку с primary на этот peer:
```bash
# На primary
ssh root@peer-host 'hostname'   # или inferno1978@peer-host для non-root
```
Если просит пароль — нужно перенастроить authorized_keys.
Если connection timed out — peer недоступен по сети (упал?).
Если Permission denied — authorized_keys не содержит public key primary.

**В: /menu прислала кнопки, но при нажатии ничего не происходит**
О: Возможно bot не запущен или упал. Проверь:
```bash
systemctl is-active xray-tg-bot
journalctl -u xray-tg-bot -n 20 --no-pager
```
Если бот активен — возможно callback не доходит до Telegram API.
Проверь доступность api.telegram.org с primary:
```bash
curl -sS -m 5 https://api.telegram.org/bot<TOKEN>/getMe
```

### По client-боту

**В: Пользователь не может привязаться через /start <token>, бот говорит «неверный токен»**
О: Проверь срок действия invite-токена. Токены одноразовые —
используются и удаляются после успешной привязки. Создай новый через
`/invite` в admin-боте.

**В: /config возвращает пустой список протоколов**
О: Возможно пользователь не привязан (нет записи в
`tg_client_bot_map.json`). Проверь привязку:
```bash
cat /var/lib/xray-installer/tg_client_bot_map.json
```
Если `tg_user_id` пользователя там нет — он не делал `/start <token>`.

**В: Пользователь получает /status, но трафик не обновляется**
О: Traf Tracking может быть отключён. Проверь в chimera TUI:
Меню → Управление трафиком → включить tracking. После включения
новый трафик начнёт отображаться (старый — нет, count started with 0).

**В: Как добавить нового пользователя VPN через client-бота?**
О: Не через client-бота — он READ-ONLY. Создай пользователя в chimera
TUI: Меню → Управление пользователями → [1] Добавить. После создания
получишь UUID. Затем в admin-боте: `/invite` — создаст одноразовую
invite-ссылку. Передай её пользователю — он откроет её в Telegram,
бот привяжет его `tg_user_id` к UUID.

### По cron-уведомлениям

**В: Я получаю дубликаты уведомлений с одного сервера**
О: Cron-скрипт использует `/tmp/xray-tg-down.stamp` файл для
дедупликации `xray_down`. Если stamp-файл не удаляется (например,
нет прав) — будет дублировать. Проверь что `/tmp` writable:
```bash
ls -la /tmp/xray-tg-down.stamp 2>/dev/null  # должен быть пустым если xray активен
```

**В: Уведомления приходят без IP в заголовке (только hostname)**
О: В `telegram.json` не задано поле `server_ip`. Добавь:
```json
{"server_ip": "<server1-ip>"}
```
И регенерируй bash-скрипт:
```bash
python3 -c "
import sys; sys.path.insert(0, '/opt/chimera')
from chimera.modules.tg_bot import tg_load, _install_monitor_cron
_install_monitor_cron()
"
```

**В: Хочу отключить уведомления об autoban**
О: В `/var/lib/xray-installer/telegram.json` измени `events.autoban`
на `false`:
```json
"events": {
  "autoban": false,
  ...
}
```
Изменения подхватятся при следующем вызове `tg_notify_event` —
регенерация не требуется.

### По cascade_peers

**В: /status показывает только primary, без peer'ов**
О: Поле `cascade_peers` пустое или отсутствует в `tg_bot.json`.
Проверь:
```bash
cat /var/lib/xray-installer/tg_bot.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('cascade_peers:', d.get('cascade_peers', 'NOT SET'))"
```

**В: /status показывает ❌ SSH exit=255 для peer**
О: SSH-связка сломалась. Проверь с primary:
```bash
ssh root@peer-host 'echo OK'  # должно вывести OK без пароля
```
Если просит пароль — нужно добавить public key primary в
`/root/.ssh/authorized_keys` на peer (для root) или
`/home/<user>/.ssh/authorized_keys` (для non-root).

**В: /status работает медленно (3+ секунды)**
О: Это нормально — каждый peer опрашивается последовательно через
SSH. Для 3 серверов это ~2-3 секунды (TCP handshake + ssh auth +
remote script). Если хочешь быстрее — можно распараллелить через
`concurrent.futures.ThreadPoolExecutor`, но это усложнит код.

---

## 12. Типовые проблемы и решения

### Проблема 1: Telegram API недоступен с сервера (ТСПУ блокировка)

**Симптом:** Bot не отвечает на /status, в journalctl — `Failed to
connect to api.telegram.org port 443`. Уведомления не приходят.

**Решение:** Настроить WARP (Cloudflare WireGuard) на сервере —
он будет маршрутизировать трафик к Telegram API через Cloudflare
edge, минуя ТСПУ-блокировку по SNI.

```bash
# Установить WARP через chimera TUI
# Или вручную:
apt install wireguard
# Создать /etc/wireguard/wg-warp.conf с Cloudflare WARP peer
systemctl enable wg-quick@wg-warp
systemctl start wg-quick@wg-warp

# Добавить route для api.telegram.org (149.154.166.x) через wg-warp
ip route add 149.154.160.0/22 dev wg-warp
```

Chimera автоматически настраивает это при установке WARP через TUI.

### Проблема 2: Конкуренция admin-ботов на нескольких серверах

**Симптом:** При разворачивании admin-бота на нескольких серверах с
одним токеном — `/status` отвечает случайный сервер, не всегда
primary.

**Решение:** Запускать admin-бота только на primary. На остальных:
```bash
systemctl stop xray-tg-bot
systemctl disable xray-tg-bot
```
Client-бот и cron-уведомления ОСТАВИТЬ — у них отдельные токены/cron.

### Проблема 3: Invite-токен не работает

**Симптом:** Пользователь открывает `https://t.me/<bot>?start=<token>`,
но бот говорит «неверный токен».

**Решение:** Токены одноразовые — используются и удаляются после
успешной привязки. Создай новый через `/invite` в admin-боте.

### Проблема 4: /restart возвращает «Неизвестный сервис»

**Симптом:** `/restart apache2` — бот отвечает «Неизвестный сервис».

**Решение:** Whitelist разрешённых сервисов ограничен:
`xray`, `nginx`, `dnscrypt`, `agh`/`adguardhome`, `fail2ban`, `warp`.
Никаких `apache2`, `mysql`, `redis` и т.д. — это специально для
безопасности.

### Проблема 5: Inline-кнопки не работают в групповом чате

**Симптом:** В группе (не в личке) кнопки не реагируют.

**Решение:** Telegram inline-кнопки работают в группах, но
`callback_query` приходит только если бот добавлен в группу как
админ. Для admin-бота рекомендуется использовать только личный чат с
`@<bot_username>`. Группы не поддерживаются по умолчанию.

### Проблема 6: В client-боте приходят 2 меню на /menu

**Симптом:** Пользователь пишет `/menu` в `@ChimeraVPNClient_bot` —
приходит **два** сообщения с inline-клавиатурой одновременно, и
непонятно какое от какого сервера. Третьего нет.

**Причина:** Client-бот запущен на нескольких серверах с **одним
токеном**. Telegram Bot API при нескольких long-pollers с одним
токеном возвращает HTTP **409 Conflict** — блокирует всех. Иногда
race condition прорывает блокировку — 2 бота успевают ответить.

В `chimera.log` на всех 3 серверах:
```
[TG-CLIENT-BOT] API error getUpdates: HTTP Error 409: Conflict
[TG-CLIENT-BOT] Poll: нет ответа от API (10 попыток подряд)
```

**Решение:** Остановить client-бота на secondary-серверах, оставить
только на primary (как уже сделано с admin-ботом):
```bash
# На server 2 и 3
systemctl stop xray-tg-client
systemctl disable xray-tg-client

# На primary (server 1) — restart для очистки 409 состояния
systemctl restart xray-tg-client
```

После рестарта primary в логе:
```
[TG-CLIENT-BOT] Client bot started
```
Больше нет 409 Conflict, long-polling работает стабильно.

**Почему так (архитектурно):** в cascade mode B primary сервер
держит всех клиентов (UUID, REALITY keys, etc), а server 2/3 —
просто cascade exit-ноды (relay для смены exit-IP). У server 2/3
нет своих клиентов — `/config` там вернул бы пустоту.

Альтернативы если нужны client-боты на нескольких серверах:
1. **Отдельные боты в @BotFather** для каждого сервера (token1 на
   primary, token2 на secondary 1, token3 на secondary 2). Тогда
   пользователь имеет 3 разных бота в контактах — сам решает к
   какому серверу подключаться. Это для standalone mode (3 разных
   VLESS-сервера с разными клиентами).
2. **Cascade_peers для client-бота** (аналогично admin-боту) —
   primary client-бот через SSH ходит на secondary и собирает
   конфиги. Тогда `/config` выдаёт список всех доступных ссылок.
   Но это большая работа (~2-3 часа) и не нужна для cascade mode B.

---

## 13. Шпаргалка по командам

### Admin-бот (только primary-сервер)

**Самые частые:**
```
/menu           — кнопки
/help           — справка
/status         — все 3 сервера
/banlist        — забаненные
/users          — пользователи
/logs xray 50   — последние 50 строк лога
/cert           — сертификаты
/version        — версия
```

**Бан-лист:**
```
/ban <ip>     — забанить
/unban <ip>   — разбанить
/banlist         — список
/whitelist       — whitelist
/wl_add <ip>  — в whitelist
/wl_del <ip>  — из whitelist
```

**Управление сервисами:**
```
/restart xray
/restart nginx
/restart dnscrypt
/restart agh
/restart fail2ban
/restart warp
/reload_nginx
/logs xray
/logs nginx 50
/logs chimera
```

**Мониторинг:**
```
/status           — каскад
/status_local     — primary
/health           — chimera diagnostics
/version          — git + uptime
/cert             — сертификаты
/geo              — GeoIP статус
/f2b              — fail2ban статус
/nodes            — exit-ноды
/probe 8.8.8.8    — TCP-ping
```

**Пользователи:**
```
/users
/users_active
/user user@example.com
/traffic          — топ-10
/traffic_top      — топ-20
/invite           — invite-ссылка
/broadcast Привет! — рассылка
```

### Client-бот (на всех серверах)

```
/start <token>    — привязка (один раз)
/menu            — кнопки
/config          — список ссылок
/qr vless        — QR-код VLESS
/status          — трафик + TTL
/protocols       — описание протоколов
/guide           — руководство
/help            — справка
```

### Cron-уведомления (приходят автоматически)

```
🔴 [host | ip] Xray не запущен!           — xray_down
🟢 [host | ip] Xray восстановился.        — xray_up
🔒 [host | ip] Сертификат истекает через N дн.  — cert_expire
🛡️ [host | ip] IP X.X.X.X забанен автоматически  — autoban
⚠️ [host | ip] Пользователь превысил лимит    — traffic_limit
📡 [host | ip] Exit-нода недоступна       — node_down
🚫 [host | ip] Порт заблокирован ТСПУ     — port_blocked
⚡ [host | ip] Port-hopping сработал      — port_hopping
📋 [host | ip] Daily health-отчёт         — health_report (08:00)
```

---

## Дополнительные ресурсы

- `chimera/modules/tg_bot.py` — реализация admin-бота + cron-уведомлений
- `chimera/modules/tg_client_bot.py` — реализация client-бота
- `docs/faq/AGH_FAQ.md` — DNS-стек (AdGuardHome + dnscrypt-proxy)
- `docs/faq/SECURITY_BAN_FAQ.md` — автобан, honeypot, IP-ban, GeoIP
- `docs/faq/VLESS_FAQ.md` — VLESS REALITY протокол
- CHANGELOG.md — все изменения (поиск "tg_bots v6")
