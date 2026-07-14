# TROUBLESHOOTING — Частые проблемы и решения

## Xray не стартует

```bash
# Проверить статус
systemctl status xray
journalctl -u xray --no-pager -n 50

# Проверить конфиг вручную
/usr/local/bin/xray run -test -config /etc/xray/config.json
```

**Частые причины:**

**1. Права на config.json (нужны 640 root:xray)**
```bash
ls -la /etc/xray/config.json
chown root:xray /etc/xray/config.json && chmod 640 /etc/xray/config.json
```

**2. Занят порт 443**
```bash
ss -tlnp | grep 443
# Если занят nginx — остановить: systemctl stop nginx
```

**3. Нет бинарника**
```bash
ls -la /usr/local/bin/xray
# Переустановить через меню: Установка и Система → Обновить Xray
```

---

## Nginx не стартует

```bash
# Проверить синтаксис конфига
nginx -t

# Посмотреть ошибки
journalctl -u nginx --no-pager -n 30
```

**Частые причины:**

**1. Unix-сокет не создан (Xray ещё не запущен)**
```bash
# Сначала запустить Xray, потом Nginx
systemctl start xray
systemctl start nginx
```

**2. Сертификат не найден**
```bash
ls /etc/letsencrypt/live/yourdomain.com/
```

**3. Порт 80 занят**
```bash
ss -tlnp | grep :80
```

---

## Certbot не получил сертификат

```bash
# Проверить DNS (домен должен указывать на IP сервера)
dig +short yourdomain.com
curl -4 ifconfig.me

# Убедиться что порт 80 открыт
ufw status | grep 80
curl -v http://yourdomain.com/.well-known/acme-challenge/test

# Попробовать вручную через webroot
certbot certonly --webroot -w /var/www/yourdomain.com -d yourdomain.com

# Если не работает webroot — попробовать standalone
systemctl stop nginx
certbot certonly --standalone -d yourdomain.com
systemctl start nginx
```

---

## Нет IPv6

```bash
# Проверить наличие глобального IPv6-адреса
ip -6 addr show scope global

# Проверить маршрут
ip -6 route show default

# Если IPv6 есть, но не работает — проверить UFW
ufw status verbose | grep v6

# Разрешить IPv6 в UFW
ufw allow 443/tcp
ufw reload
```

---

## Ошибка прав на config.json

Симптом: xray падает с кодом 23 ("permission denied")

```bash
groupadd -f xray
usermod -aG xray xray 2>/dev/null || true
chown root:xray /etc/xray/config.json
chmod 640 /etc/xray/config.json

# Проверить
id xray
ls -la /etc/xray/config.json
```

---

## APT lock (apt занят)

Симптом: `Could not get lock /var/lib/dpkg/lock-frontend`
Причина: фоновые автообновления

```bash
# Подождать завершения
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    echo "Ждём apt..."
    sleep 5
done

# Принудительно убить (осторожно!)
# kill -9 $(fuser /var/lib/dpkg/lock-frontend 2>/dev/null)
# rm -f /var/lib/dpkg/lock-frontend /var/cache/apt/archives/lock
# dpkg --configure -a
```

---

## Не найден бинарник

```bash
# xray
which xray || ls /usr/local/bin/xray
# Переустановить через меню: Установка и Система → Обновить Xray

# nginx
which nginx || ls /usr/sbin/nginx

# certbot
ls /snap/bin/certbot /usr/bin/certbot 2>/dev/null

# curl, wget
apt-get install -y curl wget
```

---

## Потерян доступ по SSH

Если SSH-порт закрыт UFW случайно — используй консоль VPS-провайдера:

```bash
# Открыть SSH
ufw allow 22/tcp
ufw reload

# Или временно выключить UFW
ufw disable
# (потом включить: ufw enable)
```

> **Профилактика:** скрипт всегда добавляет `allow 22/tcp` первым при настройке UFW, до любых других правил. EXIT TRAP также открывает порт 22 при аварийном завершении.

---

## Xray/Nginx падают после обновления системы

```bash
# Обновить конфиг systemd
systemctl daemon-reload
systemctl enable xray nginx
systemctl start xray nginx

# Проверить, не изменился ли путь к бинарнику
which xray
# Если путь изменился — обновить ExecStart в /etc/systemd/system/xray.service
```

---

## Диагностика одной командой

```bash
# Полная диагностика через установщик
sudo python3 /opt/chimera/main.py
# → Диагностика и Мониторинг → Полная диагностика

# Быстрый статус
sudo python3 /opt/chimera/main.py --status

# Логи установки
tail -100 /var/log/chimera.log

# Логи Xray
journalctl -u xray --no-pager -n 50
tail -50 /var/log/xray/error.log
```

---

## AS-маршрутизация (AS-direct routing)

**RIPE NCC API недоступен:**
```bash
# Проверить доступность
curl -v "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS8359"
# Если блокировка — префиксы загрузятся из локального кэша (SQLite)

# Принудительно сбросить кэш и перезагрузить
sudo python3 /opt/chimera/main.py --clear-asn-cache

# Обновить AS-direct префиксы
sudo python3 /opt/chimera/main.py --update-as-direct
```

**Правила AS не применяются:**
```bash
# Проверить, что config.json содержит маркер _comment: "_asn_<ASN>_auto"
grep -i "_asn_" /etc/xray/config.json

# Проверить список активных маршрутов
cat /etc/xray/as_direct_list.json
```

**Таймер автообновления не работает:**
```bash
systemctl status xray-as-direct.timer
systemctl status xray-as-direct.service
journalctl -u xray-as-direct.service -n 30
# Перезапустить вручную
systemctl restart xray-as-direct.timer
```

---

## Xray не поднялся после применения конфига (авто-откат)

```bash
# Смотрим лог изменений
grep "XRAY_APPLY_ROLLBACK\|XRAY_APPLY_FAIL" /var/log/xray-changes.log | tail -20

# Проверяем pre-apply бэкап
ls -la /etc/xray/config.json.pre-apply

# Запустить pre-flight вручную
xray run -test -config /etc/xray/config.json.pre-apply

# Применить резервную копию вручную
cp /etc/xray/config.json.pre-apply /etc/xray/config.json
systemctl restart xray
```

---

## Экспорт Clash Meta / Sing-box не создаётся

```bash
# Проверить права на директорию
ls -la /root/xray-client-configs/

# Экспортировать через меню
# → Управление пользователями → Сгенерировать Clash / Sing-box конфиг

# Если нужен YAML-формат для Clash Meta (опционально)
pip3 install pyyaml
```

---

## Ротация логов не работает

```bash
# Проверить конфиг logrotate
cat /etc/logrotate.d/xray-vless

# Принудительная ротация для проверки
logrotate -df /etc/logrotate.d/xray-vless   # dry-run
logrotate -f  /etc/logrotate.d/xray-vless   # применить

# Если logrotate не установлен
apt install logrotate
```

---

## Плановый backup не выполняется

```bash
# Проверить cron-задачу
cat /etc/cron.d/xray-backup

# Проверить лог
tail -20 /var/log/xray-scheduled-backup.log

# Запустить вручную
sudo python3 /opt/chimera/main.py --scheduled-backup

# Проверить, что cron запущен
systemctl status cron || systemctl status crond
```

---

## Блокировка входящих из РФ ломает все соединения

Симптом: после включения «Блокировка входящих из РФ» клиенты перестают подключаться.

Причина: правило DROP вставляется перед ESTABLISHED/RELATED — разрываются активные сессии.

```bash
# Немедленно отключить блокировку через меню
# → Безопасность → GeoIP блокировка → Отключить

# Или вручную через iptables
iptables -D INPUT -m set --match-set ru_block_v4 src -j DROP 2>/dev/null
ipset destroy ru_block_v4 2>/dev/null

# Проверить что правила очищены
iptables -L INPUT -n --line-numbers | grep -i "xray-ru-ingress\|ru_block"

# Перезапустить сервисы
systemctl restart xray nginx
```

> **Важно:** функция «Блокировка входящих из РФ» предназначена для **Режима B** (Entry Node в России, клиенты за рубежом). В Режиме A она заблокирует российских клиентов.

---

## Полезные пути

| Что | Путь |
|-----|------|
| Конфиг Xray | `/etc/xray/config.json` |
| Сервис Xray | `/etc/systemd/system/xray.service` |
| Лог установки | `/var/log/chimera.log` |
| Лог Xray (ошибки) | `/var/log/xray/error.log` |
| Лог Xray (доступ) | `/var/log/xray/access.log` |
| State файл | `/var/lib/xray-installer/state.json` |
| Бэкапы | `/var/backups/xray/` |
| Nginx конфиги | `/etc/nginx/sites-available/` |
| Сертификаты | `/etc/letsencrypt/live/DOMAIN/` |
| Лог изменений конфига | `/var/log/xray-changes.log` |
| Лог scheduled backup | `/var/log/xray-scheduled-backup.log` |

---

## Кластерное управление `[CL]` — Permission denied (publickey,password)

**Симптом:** все операции в меню `[CL]` завершаются ошибкой:
```
root@your-node.com: Permission denied (publickey,password).
```

**Причина:** SSH-ключ не установлен на Exit Nodes, а скрипт пробовал
только ключевую аутентификацию.

**Решение с v4.11.2:** скрипт автоматически запрашивает пароль root
при недоступности ключа. Пароль сохраняется на сессию.

**Требования для парольного режима:**
```bash
# sshpass устанавливается автоматически, но можно вручную:
apt install sshpass
```

**Ручная проверка SSH-доступа:**
```bash
# Ключевой режим
ssh -o BatchMode=yes root@your-node.com echo ok

# Парольный режим
sshpass -p 'ваш_пароль' ssh \
  -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password \
  root@your-node.com echo ok
```

**Настройка ключевой аутентификации (рекомендуется):**
```bash
# На Entry Node — сгенерировать ключ (если нет)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""

# Скопировать публичный ключ на каждую Exit Node
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@your-exit-node.com

# Проверить
ssh root@your-exit-node.com echo ok
```

После настройки ключей пароль в `[CL]` запрашиваться не будет.

---

## nginx Watchdog `[NW]` — таймер не активируется

```bash
# Проверить статус
systemctl status nginx-watchdog.timer
systemctl status nginx-watchdog.service

# Посмотреть лог
tail -50 /var/log/nginx-watchdog.log

# Перезапустить таймер вручную
systemctl restart nginx-watchdog.timer
```

---

## ipset Persistent `[IP]` — ipset не восстанавливается после reboot

```bash
# Проверить юнит
systemctl status xray-ipset-restore.service

# Проверить наличие дампа
ls -lh /etc/ipset.conf
wc -l /etc/ipset.conf

# Восстановить вручную
ipset restore -! -f /etc/ipset.conf

# Проверить что правила загружены
ipset list | grep -E "^Name:|elements:"
```

Если `/etc/ipset.conf` отсутствует — сначала сохраните текущий ipset
через меню `[IP]` → пункт `2`.

## У меня прописан свой DNS, но он не используется — это нормально?

**Краткий ответ:** Да, это ожидаемое поведение если включён **Принудительный DNS REDIRECT**.

### Что происходит

Когда включена опция **Принудительный DNS REDIRECT** (меню → Настройки сети → `DR`),
на сервере создаются iptables-правила в таблице `nat`, цепочке `PREROUTING`:

```
iptables -t nat -A PREROUTING -i awg0 -p udp --dport 53 -j REDIRECT --to-ports 5300
iptables -t nat -A PREROUTING -i awg0 -p tcp --dport 53 -j REDIRECT --to-ports 5300
```

Эти правила перехватывают **все** DNS-запросы (порт 53, UDP+TCP), приходящие от
VPN-клиентов через интерфейс `awg0`, и принудительно перенаправляют их на локальный
`dnscrypt-proxy` (по умолчанию `127.0.0.1:5300`).

**Клиент не может это обойти** на уровне приложения — даже если в настройках
VPN-клиента прописан `8.8.8.8` или `1.1.1.1`, запрос всё равно уйдёт на dnscrypt-proxy.

### Зачем это нужно

- **Защита от DNS leak** — провайдер не видит, какие домены запрашивает клиент
- **Защита от DPI-блокировки по DNS** — ТСПУ не может подменить ответ
- **Единый резолвер для всех клиентов** — dnscrypt-proxy использует DoH/DoT
  к Cloudflare/Google, что защищает от перехвата на участке клиент→DNS-сервер

### Как проверить, что это работает

**Способ 1: с клиентского устройства**

```bash
# На клиенте через VPN-туннель:
dig @8.8.8.8 google.com +short
# Если редирект работает — ответ придёт от Cloudflare (dnscrypt-proxy),
# а не от Google. Проверить через:
dig @8.8.8.8 whoami.akamai.net +short
# Должен вернуть IP exit-ноды (Cloudflare), а не 8.8.8.8
```

**Способ 2: на сервере**

```bash
# Меню → Диагностика → DN (DNS Redirect health-check)
# Или напрямую:
python3 -c "
from chimera.modules.dns_redirect import health_check_dns_redirect
import json
print(json.dumps(health_check_dns_redirect(), indent=2))
"

# Проверить правила iptables:
iptables -t nat -S PREROUTING | grep dns-redirect
# Должно показать 2 правила (udp + tcp)
```

### Как отключить

Если вам нужно использовать **кастомный DNS-сетап** (например, ваш собственный
Pi-hole или AdGuard Home), отключите принудительный редирект:

**Через меню:**

1. `sudo python3 /opt/chimera/main.py`
2. Меню → `4` (Настройки сети) → `DR` (Принудительный DNS REDIRECT)
3. Пункт `2` — Отключить

**Через команду:**

```bash
python3 -c "
from chimera.modules.dns_redirect import remove_dns_redirect
result = remove_dns_redirect()
print(result)
"
```

После отключения:
- iptables-правила удаляются (UDP + TCP, IPv4 + IPv6 если были)
- State-файл `/var/lib/xray-installer/dns_redirect.json` помечается `enabled: false`
- Systemd-unit `dns-redirect-restore.service` удаляется (правила не вернутся после reboot)
- Клиенты снова смогут использовать любой DNS-сервер на свой выбор

### Типичные проблемы

**1. После включения DNS не работает вообще**

```bash
# Проверить что dnscrypt-proxy запущен:
systemctl status dnscrypt-proxy

# Проверить что он слушает порт 5300:
ss -ulnp | grep 5300
ss -tlnp | grep 5300

# Если не запущен — перезапустить:
systemctl restart dnscrypt-proxy
sleep 2
systemctl is-active dnscrypt-proxy
```

Если dnscrypt-proxy не запускается — применяя редирект вы создадите **black-hole**
(DNS-запросы будут перехвачены, но некому ответить). Модуль `dns_redirect.py`
проверяет это перед apply и откажется применять правила если сервис не активен.

**2. IPv6 DNS не редиректится**

По умолчанию dnscrypt-proxy слушает только `127.0.0.1:5300` (IPv4). Если ваши
клиенты используют IPv6 DNS (например `::1` или `[2001:db8::1]:53`), их запросы
получат `connection refused`.

Решение — добавить `[::1]:5300` в `listen_addresses` в `/etc/dnscrypt-proxy/dnscrypt-proxy.toml`:

```toml
listen_addresses = ['127.0.0.1:5300', '[::1]:5300']
```

Затем перезапустить dnscrypt-proxy и переприменить DNS REDIRECT через меню `DR` → пункт `1`.

**3. Правила не восстанавливаются после reboot**

```bash
# Проверить systemd-unit:
systemctl status dns-redirect-restore.service

# Если disabled — включить:
systemctl enable dns-redirect-restore.service

# Запустить вручную:
systemctl start dns-redirect-restore.service
```

**4. Конфликт с ingress-блокировкой РФ-подсетей**

Принудительный DNS REDIRECT использует таблицу `nat`, цепочку `PREROUTING`.
Ingress-блокировка РФ использует таблицу `filter`, цепочку `INPUT`. Это **разные
цепочки** — конфликта быть не должно. Порядок правил (ESTABLISHED/RELATED,
whitelist ACCEPT, DROP) в `INPUT` не нарушается.

Если вы видите проблему — проверьте, что правила стоят в правильных цепочках:

```bash
# DNS REDIRECT — nat PREROUTING:
iptables -t nat -S PREROUTING | grep dns-redirect

# Ingress block — filter INPUT:
iptables -L INPUT -n --line-numbers | head -20
```

**5. После отключения AWG-интерфейса правила остались висеть**

Это нормально — iptables-правила с `-i awg0` не удаляются автоматически при
`ip link delete awg0`. Они просто не срабатывают (нет интерфейса = нет трафика).
Когда интерфейс вернётся — правила снова начнут работать.

Если хотите explicitly очистить:

```bash
python3 -c "
from chimera.modules.dns_redirect import remove_dns_redirect
remove_dns_redirect()
"
```

### См. также

- **DNS Leak Test**: Меню → Диагностика → `N` — проверка утечки DNS-запросов
- **DNSCrypt-proxy управление**: Меню → Настройки сети → `3` (оптимизация) / `R` (выбор резолверов)
- **Кастомные DNS правила**: Меню → Настройки сети → `D` (hosts / routing override в Xray)

---

## TrustTunnel — известные архитектурные ограничения

**Меню:** главное → `18` · **Upstream:** https://github.com/TrustTunnel/TrustTunnel

TrustTunnel интегрирован как 9-й протокол в `user_lifecycle.PROTOCOL_ADAPTERS`, использует официальный upstream prebuilt-бинарник `trusttunnel_endpoint` (Rust, Apache 2.0, GPG-подписан ключом AdGuard). Два ограничения зафиксированы осознанно — они не баги, а следствия дизайна upstream, которые пришлось принять при интеграции.

### 1. Только агрегированный трафик, не per-user

Апстримовский `/metrics` endpoint (Prometheus, `http://127.0.0.1:1987/metrics`) отдаёт счётчики трафика только с лейблом `protocol_type` (`http1`/`http2`/`http3`) — **без `username`**. Подтверждено в `lib/src/metrics.rs` и в `METRICS.md` upstream'а.

```prometheus
# HELP inbound_traffic_bytes Total number of bytes uploaded by clients
# TYPE inbound_traffic_bytes counter
inbound_traffic_bytes{protocol_type="http2"} 1234567
```

Per-user биллинг для TrustTunnel в текущей реализации **не поддерживается**. Трафик записывается в `traffic_accounting.record_traffic_sample` под синтетическим user_id `_aggregate` — это даёт мониторинг "есть ли вообще активность на TrustTunnel", но не позволяет атрибутировать байты конкретному пользователю. Это тот же уровень, что у FPTN и Hysteria2 в проекте (у них тоже нет per-user byte counter).

**Если per-user биллинг становится hard-требованием**, варианты:
- (a) Запускать отдельный процесс `trusttunnel_endpoint` на каждого пользователя (тяжело: 17 МБ бинарник × N пользователей, N портов).
- (b) Патчить `lib/src/metrics.rs` в upstream'е, добавляя `username` лейбл, и собирать из исходников (Rust 1.95 + CMake + libclang, ~10 мин компиляции). **Побочный эффект:** теряется GPG-верификация официальных релизов — придётся поддерживать собственный форк.

Вариант (b) в текущей реализации **не сделан осознанно** — GPG-верификация официальных бинарников считается более важной, чем per-user биллинг для протокола, который в проекте дополняющий (не основной).

### 2. Смена пользователей вызывает рестарт сервиса

Upstream TrustTunnel **не поддерживает hot-reload `credentials.toml`**. SIGHUP перезагружает только `hosts.toml` (TLS-хосты/сертификаты), но не credentials и не rules. Подтверждено в `endpoint/src/main.rs:521-542` — обработчик SIGHUP вызывает только `Core::reload_tls_hosts_settings`, который свопает `self.context.tls_demux` и больше ничего.

Любой `add`/`remove`/`block`/`unblock` для TrustTunnel → правка `credentials.toml` + `systemctl restart trusttunnel`. Рестарт длится ~1 секунду и **рвёт ВСЕ активные соединения TrustTunnel** на сервере, не только у изменяемого пользователя.

**Митигация для массовых операций:** cron-проходы (`check_ttl_expired`, `check_traffic_limits`, `run_cleanup`) обёрнуты в `user_lifecycle.batch_context()` — все правки файлов накапливаются, рестарт происходит **ровно один раз** в конце прохода, а не N раз. Контекстный менеджер поддерживает вложенность (счётчик глубины). Rollback-до-flush: при сбое любого протокола в транзакции `snap.restore()` + `_cancel_pending_restarts(protocols_list)` — демон никогда не рестартует с откаченным конфигом.

**Не митигируется:** ручное добавление/удаление пользователя через TUI-меню (пункт 18) или через клиентского Telegram-бота. Эти одиночные операции рестартуют сервис сразу. Это задокументированное поведение — если на сервере активно пользуются TrustTunnel, планировать массовые пользовательские операции на cron-окно (например, ночью) или через `batch_context()` в кастомном скрипте.

### См. также

- **Установка/удаление:** Меню → `18` (TrustTunnel) → `1` (Установить) / `8` (Удалить)
- **Cron-задачи:** `/etc/cron.d/trusttunnel` (health + stats, каждые 5 мин) — устанавливается автоматически при install, убирается при uninstall
- **Логи:** `/var/log/xray-trusttunnel.log` (lifecycle), `/var/log/trusttunnel-endpoint.log` (binary stdout/stderr)
- **VPS-чеклист для реального тестирования:** [`docs/trusttunnel-vps-checklist.md`](docs/trusttunnel-vps-checklist.md)

