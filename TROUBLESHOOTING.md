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
sudo python3 /opt/vless-ultimate/main.py
# → Диагностика и Мониторинг → Полная диагностика

# Быстрый статус
sudo python3 /opt/vless-ultimate/main.py --status

# Логи установки
tail -100 /var/log/vless-install.log

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
sudo python3 /opt/vless-ultimate/main.py --clear-asn-cache

# Обновить AS-direct префиксы
sudo python3 /opt/vless-ultimate/main.py --update-as-direct
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
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup

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
| Лог установки | `/var/log/vless-install.log` |
| Лог Xray (ошибки) | `/var/log/xray/error.log` |
| Лог Xray (доступ) | `/var/log/xray/access.log` |
| State файл | `/var/lib/xray-installer/state.json` |
| Бэкапы | `/var/backups/xray/` |
| Nginx конфиги | `/etc/nginx/sites-available/` |
| Сертификаты | `/etc/letsencrypt/live/DOMAIN/` |
| Лог изменений конфига | `/var/log/xray-changes.log` |
| Лог scheduled backup | `/var/log/xray-scheduled-backup.log` |
