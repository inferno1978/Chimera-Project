# Port Knocking в Chimera — FAQ по динамическому ACL

Это подробный гайд по модулю `chimera/modules/port_knocking.py` — защите
VPN-портов (443, 9443) от обнаружения публичными сканерами (Censys, Shodan,
Shadowserver) через port knocking на базе iptables + ipset (без внешних
демонов типа knockd).

> **Краткая суть:**
> - Все SYN-пакеты на защищаемый порт по умолчанию **DROP** (как будто порт
>   закрыт)
> - Клиент делает N SYN-retry за W секунд (нативное TCP-поведение)
> - iptables через `recent` module считает SYN — при достижении N за W
>   секунд IP добавляется в ipset `xray_knocked` (с TTL timeout)
> - Дальнейшие SYN с этого IP проходят (ipset → ACCEPT), VPN-клиент
>   подключается
> - Через TTL секунд без новых соединений — IP автоматически удаляется
>   из ipset (нужно снова постучаться)
> - IP из `clients_wl` (whitelist) — приоритетнее knocking, сразу ACCEPT
> - IP из `xray_manual_ban` (бан-лист) — DROP всегда, knocking не помогает

---

## Оглавление

1. [Зачем это нужно — кейс](#1-зачем-это-нужно--кейс)
2. [Чем отличается от honeypot, autoban, ingress-GeoIP](#2-чем-отличается-от-honeypot-autoban-ingress-geoip)
3. [Как это работает — техническая архитектура](#3-как-это-работает--техническая-архитектура)
4. [Инициализация с нуля — пошаговая](#4-инициализация-с-нуля--пошаговая)
5. [Все параметры и их значения](#5-все-параметры-и-их-значения)
6. [TUI-меню — все действия](#6-tui-меню--все-действия)
7. [Файлы на сервере](#7-файлы-на-сервере)
8. [Совместимость с другими модулями Chimera](#8-совместимость-с-другими-модулями-chimera)
9. [Тюнинг параметров под свой кейс](#9-тюнинг-параметров-под-свой-кейс)
10. [Типовые проблемы и решения](#10-типовые-проблемы-и-решения)
11. [Вопрос-ответ](#11-вопрос-ответ)
12. [Шпаргалка](#12-шпаргалка)

---

## 1. Зачем это нужно — кейс

**Проблема:** Censys, Shodan, Shadowserver и другие массовые сканеры
регулярно опрашивают все IPv4 — проверяют какие порты открыты, какой
TLS-handshake отвечают. VLESS REALITY-сервер на :443 легко детектируется
по характерному TLS-fingerprint'у (REALITY imitates real SNI but has
subtle differences). После обнаружения:
- РКН может заблокировать IP по TLS-fingerprint
- Автоматические эксплойт-фреймворки начинают probe на уязвимости
- Логи xray засоряются TLS-error'ами от сканеров
- Сообщества type "blocked-IP" начинают публиковать твой IP

**Решение port knocking:**
- Сканер делает **1 SYN** на :443 → сервер DROP (как будто порт закрыт)
- Сканер переходит к следующему IP — не добавляет в базу
- Реальный VPN-клиент делает TCP handshake retry (3-5 SYN за 5-10 сек —
  стандартное TCP-поведение при дропе)
- iptables `recent` module считает SYN — при достижении N за W секунд
  IP добавляется в ipset `xray_knocked` (временный whitelist)
- Клиент успешно завершает TCP handshake → REALITY handshake → подключён
- Через TTL секунд без новых соединений IP удаляется из ipset (next time
  нужно снова постучаться)

**Результат:** Censys не видит VLESS-сервис на твоём IP. Логи чистые от
сканер-мусора. Атакующим нужно знать "magic knock sequence" (N SYN за
W сек), что не является стандартным паттерном.

**Важно:** port knocking **снижает** обнаружение, **не исключает**
полностью. Если злоумышленник знает про защиту и сниффит трафик — он
увидит N SYN перед реальным подключением и сможет повторить. Это
дополнительный фактор защиты, не панацея.

---

## 2. Чем отличается от honeypot, autoban, ingress-GeoIP

| Модуль | Подход | Когда срабатывает | Цель |
|---|---|---|---|
| **Port Knocking** (этот) | Проактивный: DROP по умолчанию, ACCEPT после N SYN | На TCP-SYN | Спрятать сервис от сканеров |
| **Honeypot** | Реактивный: открыть фейковый порт, банить при подключении | На TCP-connect | Ловить активных сканеров |
| **AutoBan** | Реактивный: бан по 10+ TLS errors за 60 сек | На TLS handshake errors | Банить брутфорс/зондирование |
| **Ingress GeoIP (block РФ)** | Проактивный: DROP по подсетям РФ | На IP-source | Блокировать все российские подключения |
| **fail2ban** | Реактивный: бан по N failed login attempts | На auth log | Банить brute-force auth |
| **clients_wl** | Static: IP всегда ACCEPT | На IP-source | Защитить админа от автобана |

**Идеальная комбинация:**
1. Port Knocking на :443 — спрятать сервис от Censys/Shodan
2. Ingress GeoIP — DROP всех РФ-подсетей (включая РКН-сканеры)
3. AutoBan — банить TLS-brute-force (после обнаружения сервиса)
4. Honeypot — ловить тех, кто стучится на нестандартные порты
5. fail2ban — банить SSH brute-force
6. clients_wl — статичный whitelist для админа (чтобы его не забанили)

---

## 3. Как это работает — техническая архитектура

### iptables правила (для порта 443, knock_count=3, window=10s, ttl=3600s)

```bash
# 1. ipset с TTL — временный whitelist (1 час = 3600 сек)
ipset create xray_knocked hash:ip timeout 3600 exist

# 2. INSERT правила (обработка ДО knocking — на стороне сервера)
#    Порядок важен — сверху вниз, первое совпадение = действие

# 2a. DROP по бан-листу (priority over knocking — бан навсегда)
iptables -I INPUT 1 -p tcp --dport 443 \
         -m set --match-set xray_manual_ban src -j DROP \
         -m comment --comment "chimera-port-knocking:DROP-ban"

# 2b. ACCEPT из static whitelist (priority over knocking — постоянные клиенты)
iptables -I INPUT 2 -p tcp --dport 443 \
         -m set --match-set clients_wl src -j ACCEPT \
         -m comment --comment "chimera-port-knocking:ACCEPT-wl"

# 2c. ACCEPT из dynamic whitelist (после knocking)
iptables -I INPUT 3 -p tcp --dport 443 \
         -m set --match-set xray_knocked src -j ACCEPT \
         -m comment --comment "chimera-port-knocking:ACCEPT-knocked"

# 3. APPEND правила (knocking logic — после whitelist/ban checks)

# 3a. Каждый SYN добавляется в recent list (имя KNOCK443 — per-port)
iptables -A INPUT -p tcp --dport 443 --syn \
         -m recent --name KNOCK443 --set \
         -m comment --comment "chimera-port-knocking:recent-set"

# 3b. Если N SYN за W секунд → добавить IP в xray_knocked (с TTL timeout)
iptables -A INPUT -p tcp --dport 443 --syn \
         -m recent --name KNOCK443 --rcheck --seconds 10 --hitcount 3 \
         -m set --add-set xray_knocked src \
         -m comment --comment "chimera-port-knocking:recent-check-add"

# 3c. DROP всех остальных SYN (default deny — "порт закрыт" для сканеров)
iptables -A INPUT -p tcp --dport 443 --syn -j DROP \
         -m comment --comment "chimera-port-knocking:DROP-default"
```

### Логика работы

| Сценарий | Что происходит |
|---|---|
| Сканер делает 1 SYN на :443 | 2a-2c не совпадают (IP не в бан/wl/knocked) → 3a добавляет в recent → 3b проверяет: < 3 за 10с → пропустить → 3c DROP. Сканер видит "порт закрыт". |
| Сканер делает ещё 2 SYN (всего 3 за 10с) | 3a обновляет recent → 3b: hitcount=3, seconds=10 → условие выполнено → IP добавлен в xray_knocked (с TTL=3600с) → 3c DROP (но уже поздно, IP в whitelist для будущих SYN). |
| Клиент делает 4-й SYN | 2c совпадает (IP в xray_knocked) → ACCEPT. TCP handshake завершается → REALITY handshake → клиент подключён. |
| Сканер делает 4-й SYN после knocking | Тоже ACCEPT (т.к. IP в xray_knocked). Но сканер уже ушёл после первого DROP — обычно не возвращается. |
| IP в `clients_wl` (whitelist админа) | 2b → ACCEPT сразу, без knocking. |
| IP в `xray_manual_ban` | 2a → DROP, knocking не поможет. |
| После TTL=3600 сек без соединений | ipset автоматически удаляет IP (timeout). Следующее подключение — снова knocking. |

### ipset `xray_knocked`

Создаётся модулем с `timeout` (TTL на каждый IP). После install — при
добавлении IP, ему автоматически присваивается TTL (по умолчанию 3600
сек = 1 час). Каждый новый пакет от этого IP продлевает TTL (если
используется `-exist` flag в ipset add).

Структура: `hash:ip` (только IP, без портов). Один IP — одна запись.

### `recent` module (`xt_recent`)

Linux kernel module для счёта пакетов в sliding window. Создаёт
таблицы в `/proc/net/xt_recent/`. Имя таблицы — `KNOCK{port}` (например
`KNOCK443`, `KNOCK9443`) для per-port изоляции.

Лимиты: `xt_recent` имеет дефолтный лимит в 16 IP-таблиц на систему
(`ip_list_tot = 100` IP-entries per table, `ip_pkt_list_tot = 20`
packets per IP). Для port knocking этого достаточно.

---

## 4. Инициализация с нуля — пошаговая

### Шаг 1: проверить что модуль доступен в chimera

```bash
cd /opt/chimera
python3 -c "from chimera.modules.port_knocking import do_manage_port_knocking; print('OK')"
```

### Шаг 2: запустить chimera TUI

```bash
cd /opt/chimera && python3 -m chimera
```

В главном меню найти пункт **`PK`** (рядом с `P` Honeypot) — `🚪 Port
Knocking — динамический ACL — Censys/Shodan не найдут`.

### Шаг 3: настроить параметры (перед включением)

В меню `[PK]`:
- `[2]` Configure parameters → knock_count=3, knock_window_sec=10,
  whitelist_ttl_sec=3600 (или свои значения)
- `[3]` Add port → добавить порты для защиты (443, 9443)

### Шаг 4: включить knocking

В меню `[PK]`:
- `[1]` Enable port knocking → бот установит iptables rules + создаст
  ipset, обновит state file

**ВАЖНО:** после включения — все новые TCP-соединения требуют knocking.
Если VPN-клиент сейчас подключён — он останется в ipset пока действует
TTL. Новые клиенты должны "постучаться" (3 SYN за 10 сек —
автоматическое TCP retry behavior).

### Шаг 5: проверить

В меню `[PK]`:
- `[4]` Status — должен показать active rules + ipset size + recent
  table stats
- `[5]` Test knocking — отправляет N SYN на localhost:port, проверяет
  что 127.0.0.1 попал в xray_knocked

### Шаг 6: проверить на Censys/Shodan

После включения knocking — подожди 24 часа (пока Censys обновит свою
базу). Затем зайди на:
- https://search.censys.io/hosts/<твой-IP>
- https://www.shodan.io/host/<твой-IP>

Сервис на :443 должен отсутствовать (или показывать "connection
refused"). Если всё ещё виден — проверь что клиенты реально делают
knocking (в `/proc/net/xt_recent/KNOCK443`).

---

## 5. Все параметры и их значения

State file: `/var/lib/xray-installer/port_knocking.json`

```json
{
  "enabled": false,
  "ports": [443],
  "knock_count": 3,
  "knock_window_sec": 10,
  "whitelist_ttl_sec": 3600,
  "log_success": false,
  "installed_at": null
}
```

| Поле | Тип | Дефолт | Диапазон | Описание |
|---|---|---|---|---|
| `enabled` | bool | false | — | Активированы ли правила |
| `ports` | list[int] | [443] | 1-65535 | Список портов для защиты (можно несколько — 443, 9443) |
| `knock_count` | int | 3 | 1-20 | Сколько SYN в окне = "правильный knock". Меньше = быстрее, но сканеры легче пройдут. Больше = надёжнее, но клиенты могут тайм-аутнуть. |
| `knock_window_sec` | int | 10 | 1-300 | Окно времени для подсчёта SYN. Меньше = строже (медленные клиенты не успеют). Больше = лояльнее (но даёт сканерам больше времени). |
| `whitelist_ttl_sec` | int | 3600 | 60-2592000 (60с — 30д) | TTL IP в xray_knocked. Меньше = чаще knocking (более безопасно). Больше = реже knocking (удобнее для клиентов). |
| `log_success` | bool | false | — | Логировать successful knocks в chimera.log (для дебага — узнать какие IP постучались). |
| `installed_at` | str | null | ISO 8601 | Когда модуль был активирован (автозаполняется). |

### Рекомендации по значениям

| Сценарий | knock_count | window_sec | ttl_sec | Заметка |
|---|---|---|---|---|
| Дефолт (VLESS REALITY на 443) | 3 | 10 | 3600 | Универсально — покрывает Linux/macOS/iOS/Android TCP retry |
| Высокая безопасность | 5 | 15 | 1800 | Сложнее для сканеров, чаще knocking (30 мин TTL) |
| Лояльный | 2 | 5 | 86400 (24ч) | Быстрее подключение, реже knocking |
| SSH (порт 22) | 3 | 10 | 600 (10 мин) | Короткий TTL — кто постучался 10 минут назад, должен снова |

### Как TCP retry работает на клиентах

| ОС | Default retries | Pattern | Σ SYN за 10с |
|---|---|---|---|
| Linux (`tcp_syn_retries=6`) | 6 | 1s, 2s, 4s, 8s, 16s, 32s | 4 |
| Windows 10/11 | 3-5 | ~1s apart | 5-9 |
| macOS / iOS | 5-6 | 0.5s, 1s, 2s, 4s, 8s | 5 |
| Android (Linux kernel) | 6 | 1s, 2s, 4s, 8s, 16s | 4 |

Все ОС делают минимум 4 SYN за 10 секунд → knock_count=3 покрывает все.

---

## 6. TUI-меню — все действия

Войти: `cd /opt/chimera && python3 -m chimera` → `[PK]`

| Пункт | Что делает |
|---|---|
| `[1]` Enable/disable | Включить/выключить knocking (install/remove iptables rules) |
| `[2]` Configure parameters | Редактировать knock_count, knock_window_sec, whitelist_ttl_sec |
| `[3]` Add/remove port | Добавить или убрать порт из защиты (443, 9443, и т.д.) |
| `[4]` Status | Показать активные rules, размер ipset, recent table stats |
| `[5]` Test knocking | Отправить N SYN на localhost:port, проверить что IP попал в xray_knocked |
| `[6]` View knocked IPs | Показать текущий список IP в xray_knocked (с TTL для каждого) |
| `[Q]` | Назад в главное меню |

---

## 7. Файлы на сервере

| Файл | Назначение |
|---|---|
| `/var/lib/xray-installer/port_knocking.json` | State file (конфиг + installed_at timestamp) |
| `/var/log/chimera.log` | Логи с префиксом `[PK]` — install/remove/test events |
| `/proc/net/xt_recent/KNOCK443` | Recent table для порта 443 (kernel, read-only для просмотра) |
| `/proc/net/xt_recent/KNOCK9443` | Recent table для порта 9443 |
| ipset `xray_knocked` | Временный whitelist (с TTL timeout) |
| `/etc/ipset.conf` | Сохранённое состояние ipset (после `_pk_persist()`) |
| `/etc/iptables/rules.v4` | Сохранённые iptables rules (после `_pk_persist()` через netfilter-persistent) |

---

## 8. Совместимость с другими модулями Chimera

| Модуль | Совместимость | Заметка |
|---|---|---|
| **Honeypot** | ✅ Полная | Honeypot открывает фейковый порт, knocking защищает реальный — не конфликтуют |
| **AutoBan** | ✅ Полная | AutoBan банит по TLS errors (после handshake), knocking защищает до handshake |
| **Ingress GeoIP (block РФ)** | ⚠️ Порядок правил | Ingress GeoIP должен быть ВЫШЕ knocking в iptables (DROP для РФ до knocking-check). Если оба в INPUT chain — порядок важен. |
| **fail2ban** | ✅ Полная | fail2ban на SSH, knocking на VPN — не конфликтуют |
| **Port Hopping (ТСПУ)** | ⚠️ Конфликт | Port hopping использует iptables REDIRECT для диапазона портов. Если knocking включён на том же порту — может конфликтовать. Решение: knocking на 443, hopping на диапазон 8000-9000. |
| **Telemt (MTProto proxy)** | ⚠️ Не рекомендуется | Telemt-клиенты (Telegram) не делают retry TCP handshake — упал → упал. Не включать knocking на Telemt-порт. |
| **clients_wl (whitelist)** | ✅ Полная | `clients_wl` приоритетнее knocking — IP в whitelist сразу ACCEPT |
| **xray_manual_ban** | ✅ Полная | `xray_manual_ban` приоритетнее — DROP всегда, knocking не помогает |
| **fw_guard (snapshot/recovery)** | ✅ Полная | fw_guard восстанавливает все iptables rules включая knocking (если они были в snapshot) |

### Порядок iptables INPUT rules (для нескольких модулей)

```
1. DROP по xray_manual_ban         (бан навсегда — priority)
2. ACCEPT по clients_wl             (whitelist — priority)
3. ACCEPT по xray_knocked           (knocking — для тех кто постучался)
4. ... (ingress GeoIP rules, если включены — обычно через DROP ipset xray_ru_block)
5. recent --set KNOCK{port}        (count SYN)
6. recent --rcheck KNOCK{port} → add-set xray_knocked (knocking logic)
7. DROP default                    (закрыть порт)
```

---

## 9. Тюнинг параметров под свой кейс

### Как узнать — сколько SYN реально делают мои клиенты?

1. **Включить `log_success=true`** в state file
2. Подождать 1 час
3. Посмотреть в chimera.log — какие IP постучались:
   ```bash
   grep "knocking success" /var/log/chimera.log | tail -50
   ```
4. Если все клиенты попадают в knocked-list за 1-2 SYN — knock_count=3 слишком высокий. Можно снизить до 2.
5. Если некоторые клиенты не попадают (timeout) — увеличить knock_window_sec.

### Альтернатива: tcpdump на 30 секунд

```bash
# На сервере с включённым knocking
tcpdump -i any -nn -c 1000 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and dst port 443' | head -50
```

Посмотреть — сколько SYN делает каждый IP. Если видишь 3-5 SYN за 10 сек с одного IP — это нормальный клиент (retry pattern). Если 1 SYN и больше не видно — это сканер.

### Что если клиенты жалуются на медленное подключение?

Причина: `knock_window_sec` слишком короткий, клиенты не успевают сделать N SYN.

Решение:
- Увеличить `knock_window_sec` (например с 10 → 20)
- Или уменьшить `knock_count` (с 3 → 2)

### Что если Censys всё ещё видит сервис?

Причины:
1. **TTL слишком длинный** — после того как твой клиент постучался, его IP в whitelist 1 час. Сканер с того же IP (или botnet) может подключиться без knocking. Решение: уменьшить `whitelist_ttl_sec` (с 3600 → 600).
2. **knock_count слишком маленький** — сканеры тоже делают retry. Решение: увеличить `knock_count` (с 3 → 5).
3. **Censys давно обновлял базу** — подожди 24-48 часов после включения knocking, затем проверь снова.
4. **KNocking не включён** — проверить через `/var/lib/xray-installer/port_knocking.json` (enabled: true) и iptables -S INPUT | grep chimera-port-knocking

---

## 10. Типовые проблемы и решения

### Проблема 1: После включения knocking — клиенты не могут подключиться

**Симптом:** Все VPN-клиенты отключились после `[PK] → [1] Enable`

**Причина:** `knock_count` слишком высокий (например 5), клиенты не делают так много SYN-retry, или `knock_window_sec` слишком короткий (например 2 сек, а клиенты делают retry каждые 4 сек).

**Решение:**
```bash
# Quick fix — отключить knocking
cd /opt/chimera && python3 -c "
import sys; sys.path.insert(0, '.')
from chimera.modules.port_knocking import _pk_state_load, _pk_state_save, _pk_remove
_pk_remove()
state = _pk_state_load()
state['enabled'] = False
_pk_state_save(state)
print('Knocking disabled — клиенты должны снова подключиться')
"
```

Затем настроить мягче: `knock_count=2`, `knock_window_sec=20`.

### Проблема 2: `recent: table full, dropping` в dmesg

**Симптом:** dmesg показывает `recent: table full, dropping packets`

**Причина:** `xt_recent` модуль имеет лимит на количество IP-entries в
таблице (дефолт 100 на таблицу). Сканеры забивают таблицу.

**Решение:** увеличить лимит `ip_list_tot` в `/etc/modprobe.d/xt_recent.conf`:
```
options xt_recent ip_list_tot=1000
```
Перезагрузить модуль или перезапустить сервер.

### Проблема 3: ipset `xray_knocked` не создаётся

**Симптом:** `[PK] → [4] Status` показывает "ipset not found"

**Причина:** ipset не установлен, или нет прав на создание.

**Решение:**
```bash
apt install ipset  # Debian/Ubuntu
# Проверить:
ipset list xray_knocked
# Если нет — переустановить knocking:
cd /opt/chimera && python3 -c "
from chimera.modules.port_knocking import _pk_state_load, _pk_install
_pk_install(_pk_state_load())
"
```

### Проблема 4: knocking работает, но Censys всё ещё видит сервис

**Симптом:** Censys показывает :443 как открытый через 24 часа после включения

**Причина:** Censys мог получить данные ДО включения knocking, или
knock_count слишком маленький и Censys делает retry.

**Решение:**
1. Подождать ещё 24-48 часов (Censys обновляется не сразу)
2. Проверить через nmap: `nmap -vv -sS <твой-IP> -p 443` — должен показать `filtered` или `closed`
3. Увеличить `knock_count` (с 3 → 5)
4. Уменьшить `whitelist_ttl_sec` (с 3600 → 600 — 10 мин, чтобы botnet-IP'ы не задерживались в whitelist)

### Проблема 5: SSH отключился после включения knocking

**Симптом:** Не могу SSH на сервер после `[PK] → Enable`

**Причина:** knocking включён на SSH-порт (22) — а SSH-клиент может не делать retry быстро.

**Решение:** knocking по умолчанию включается только на порты из
`state['ports']` (обычно 443, 9443). Если 22 случайно добавлен —
убрать через `[PK] → [3] Remove port → 22`. SSH не должен быть под
knocking (используй fail2ban + key-only auth вместо).

---

## 11. Вопрос-ответ

**В: Чем это отличается от fail2ban?**

О: fail2ban — реактивный (банит после N failed login attempts в логе).
Port knocking — проактивный (DROP с самого начала, ACCEPT только после
"magic knock"). fail2ban защищает от brute-force (после обнаружения
сервиса), port knocking — прячет сервис (до обнаружения).

**В: Чем это отличается от honeypot?**

О: Honeypot — открывает фейковый порт, банит каждого кто подключился.
Port knocking — закрывает реальный порт, открывает только для тех кто
сделал N SYN-retry. Honeypot ловит активных сканеров, port knocking
прячет реальный сервис.

**В: Knocking безопаснее чем просто DROP всего?**

О: Knocking **добавляет** latency к первому подключению (3 SYN за 10
сек ≈ 3-10 секунд задержки). После первого успешного knocking IP в
whitelist на TTL (1 час) — следующие подключения без задержки. Это
баланс между безопасностью (DROP по умолчанию) и удобством ( whitelist
для реальных клиентов).

**В: Что если злоумышленник знает про knocking и сниффит трафик?**

О: Port knocking **снижает** обнаружение, не исключает полностью.
Атакующий со сниффером увидит N SYN перед реальным подключением и
сможет повторить. Это дополнительный фактор защиты, не панацея. Для
полной защиты нужен VPN-over-VPN (например VLESS REALITY + AWG
внешний слой).

**В: Работает ли это с Telemt (MTProto proxy)?**

О: НЕ рекомендуется. Telemt-клиенты (Telegram) обычно делают 1 SYN и
если дроп — отключаются (не retry). Knocking сломает Telemt. Используй
на VLESS :443 — там клиенты делают TCP retry.

**В: Можно ли использовать на cascade-exit ноды (server 2, 3)?**

О: Да, но осторожно — exit-ноды принимают трафик от primary-сервера
(server 1), который тоже будет делать TCP retry. Включи knocking на
exit-нодах только если знаешь что primary-сервер делает retry быстро.

**В: Что если knock_count=1?**

О: Это эквивалентно **отсутствию knocking** — любой SYN проходит. Не
имеет смысла. Минимум 2 (тогда 1 SYN = DROP, 2 SYN = ACCEPT).

**В: Knocking работает, но через час нужно снова knocking — неудобно**

О: Увеличь `whitelist_ttl_sec` (с 3600 → 86400 = 24 часа). Клиенты
будут реже knocking. Минус — если IP угонят (например через DHCP),
botnet-IP тоже будет в whitelist 24 часа.

**В: Можно ли включить knocking сразу на нескольких портах?**

О: Да — добавь порты через `[PK] → [3] Add port` (например 443 и
9443). Каждый порт получит свой recent table (`KNOCK443`, `KNOCK9443`)
и независимый knocking. ipset `xray_knocked` один на все порты — IP в
whitelist проходит на все защищённые порты.

**В: Я отключил knocking — но клиенты всё ещё не могут подключиться**

О: Проверь что iptables rules удалены:
```bash
iptables -S INPUT | grep chimera-port-knocking
# должно быть пусто
```
Если есть — удалить вручную:
```bash
while iptables -D INPUT -m comment --comment "chimera-port-knocking:DROP-default" 2>/dev/null; do :; done
# повторить для всех comment-patterns
```
Также проверить ipset:
```bash
ipset destroy xray_knocked  # если остался
```

**В: Knocking включён, но `iptables -S` не показывает правила**

О: Возможно install упал из-за ошибки. Проверь:
```bash
grep "PK.*ERROR" /var/log/chimera.log | tail -20
```
Или переустанови через TUI: `[PK] → [1] Disable → [1] Enable`.

**В: Можно ли использовать knocking без chimera?**

О: Да — это стандартные iptables/ipset правила. Можно написать bash
скрипт. Но chimera даёт TUI, state file, idempotent install/remove,
интеграцию с fw_guard (snapshot/recovery), TG-уведомления. Без chimera
— придётся всё вручную.

---

## 12. Шпаргалка

### Quick start (TUI)

```bash
cd /opt/chimera && python3 -m chimera
# → [PK] Port Knocking
# → [3] Add port → 443
# → [2] Configure → knock_count=3, window=10, ttl=3600
# → [1] Enable
```

### Quick check

```bash
# Status
iptables -S INPUT | grep chimera-port-knocking
ipset list xray_knocked | head -20
cat /proc/net/xt_recent/KNOCK443 | head -20
cat /var/lib/xray-installer/port_knocking.json | python3 -m json.tool
```

### Quick disable (emergency)

```bash
cd /opt/chimera && python3 -c "
import sys; sys.path.insert(0, '.')
from chimera.modules.port_knocking import _pk_state_load, _pk_state_save, _pk_remove
_pk_remove()
state = _pk_state_load()
state['enabled'] = False
_pk_state_save(state)
print('Knocking disabled')
"
```

### Manual rule install (without TUI)

```bash
# ipset
ipset create xray_knocked hash:ip timeout 3600 exist

# iptables (port 443, knock=3, window=10, ttl=3600)
iptables -I INPUT 1 -p tcp --dport 443 -m set --match-set xray_manual_ban src -j DROP -m comment --comment "chimera-port-knocking:DROP-ban"
iptables -I INPUT 2 -p tcp --dport 443 -m set --match-set clients_wl src -j ACCEPT -m comment --comment "chimera-port-knocking:ACCEPT-wl"
iptables -I INPUT 3 -p tcp --dport 443 -m set --match-set xray_knocked src -j ACCEPT -m comment --comment "chimera-port-knocking:ACCEPT-knocked"
iptables -A INPUT -p tcp --dport 443 --syn -m recent --name KNOCK443 --set -m comment --comment "chimera-port-knocking:recent-set"
iptables -A INPUT -p tcp --dport 443 --syn -m recent --name KNOCK443 --rcheck --seconds 10 --hitcount 3 -m set --add-set xray_knocked src -m comment --comment "chimera-port-knocking:recent-check-add"
iptables -A INPUT -p tcp --dport 443 --syn -j DROP -m comment --comment "chimera-port-knocking:DROP-default"
```

### Manual rule remove

```bash
# Delete all rules with our comment
for tag in "DROP-ban" "ACCEPT-wl" "ACCEPT-knocked" "recent-set" "recent-check-add" "DROP-default"; do
    while iptables -D INPUT -m comment --comment "chimera-port-knocking:${tag}" 2>/dev/null; do :; done
done

# Flush + destroy ipset
ipset flush xray_knocked 2>/dev/null
ipset destroy xray_knocked 2>/dev/null
```

### Связанные ресурсы

- `chimera/modules/port_knocking.py` — реализация модуля
- `tests/test_port_knocking.py` — 52 unit-теста
- `docs/faq/SECURITY_BAN_FAQ.md` — honeypot/autoban/ingress-GeoIP
- `docs/faq/AGH_FAQ.md` — DNS-стек (AdGuardHome + dnscrypt-proxy)
- `docs/faq/VLESS_FAQ.md` — VLESS REALITY протокол
- https://github.com/shanker-sec/docker-dynamic-ACL — вдохновивший нас проект
- https://habr.com/ru/articles/855536/ — статья shanker-sec про port knocking
