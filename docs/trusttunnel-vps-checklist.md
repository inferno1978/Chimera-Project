# TrustTunnel — VPS-чеклист для реального тестирования

**Цель:** sanity-check интеграции TrustTunnel на реальном VPS перед боевым использованием. Чеклист зафиксирован как часть документации проекта, чтобы его можно было прогнать без необходимости собирать шаги по переписке.

**Контекст:** локальный sanity-check (бинарь стартует, `/metrics` отвечает, deep-link roundtrips, multi-user работает) выполнен в Phase 0. Этот чеклист покрывает то, что нельзя проверить без реального VPS и реального клиентского приложения — end-to-end handshake с туннелированием трафика.

**Ожидаемое время:** 30–60 минут (включая ожидание DNS-пропагации для Let's Encrypt).

---

## Предусловия

- [ ] Тестовый VPS того же класса, что используется для остального тестирования проекта (Ubuntu 22.04/24.04, root-доступ).
- [ ] Домен с A-записью, указывающей на IP тестового VPS. Домен НЕ должен совпадать с доменами других протоколов на этом VPS (VLESS/NaiveProxy/FPTN/MTProto) — TrustTunnel требует свой домен для TLS-сертификата.
- [ ] Порты 80/tcp (для ACME HTTP-01 challenge) и 8443/tcp + 8443/udp свободны на тестовом VPS.
- [ ] Тестовое устройство (смартфон/macOS) с установленным TrustTunnel-клиентом — https://github.com/TrustTunnel/TrustTunnelClient (Flutter+Rust, iOS/Android/macOS).

---

## Шаг 1 — Установка через меню проекта

```bash
# На тестовом VPS:
cd /opt/chimera  # или где установлен проект
sudo python3 main.py
# Главное меню → 18 (TrustTunnel) → 1 (Установить)
# Ввести:
#   - домен (например tt-test.example.com)
#   - порт [Enter=8443]
#   - email для Let's Encrypt (можно пропустить)
```

**Проверки после установки:**

- [ ] `systemctl is-active trusttunnel` → `active`
- [ ] `ss -tlnp | grep 8443` → процесс `trusttunnel_endpoint` слушает TCP 8443
- [ ] `ss -ulnp | grep 8443` → процесс `trusttunnel_endpoint` слушает UDP 8443 (HTTP/3/QUIC)
- [ ] `curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:1987/health-check` → `200`
- [ ] `curl -s http://127.0.0.1:1987/metrics | grep -E "client_sessions|inbound_traffic"` → метрики присутствуют (пока с нулевыми значениями — это нормально, клиентов ещё нет)
- [ ] `cat /etc/cron.d/trusttunnel` → файл существует, содержит `--trusttunnel-health` и `--trusttunnel-stats` строки с интервалом `*/5 * * * *`
- [ ] `cat /etc/letsencrypt/renewal-hooks/deploy/trusttunnel-reload.sh` → файл существует, содержит `systemctl reload trusttunnel`
- [ ] `ls /etc/letsencrypt/live/<домен>/{fullchain,privkey}.pem` → сертификат получен
- [ ] `grep cert_chain_path /opt/trusttunnel/hosts.toml` → `/etc/letsencrypt/live/<домен>/fullchain.pem` (НЕ `certs/cert.pem` — self-signed визарда остаётся только как файловый фолбэк)
- [ ] `ufw status | grep 8443` → порты 8443/tcp и 8443/udp открыты с комментарием `TRUSTTUNNEL`

> **Если установка упала с «setup_wizard exited 124»** — на ранних релизах
> это upstream-дедлок визарда (`--cert-type provided` в non-interactive);
> + запускает визард без cert-флагов и подменяет `hosts.toml` на LE.
> Лечение: обновить проект (`git pull`) и повторить установку. Подробности:
> `TROUBLESHOOTING.md` → TrustTunnel → п. 3.

---

## Шаг 2 — Добавление тестового пользователя

```bash
# Через меню:
# Главное меню → 2 (Управление пользователями) → добавить пользователя
# Email: testuser@example.com
# Протоколы: выбрать trusttunnel (можно + vless для полной проверки)
```

**Альтернативно — через Python-REPL (для отладки):**

```python
sudo python3 -c "
from chimera.modules.user_lifecycle import add_user
result = add_user(
    email='testuser@example.com',
    protocols=['trusttunnel'],
    uuid_str='test-uuid-1234',
)
print(result)
"
```

**Проверки:**

- [ ] `cat /opt/trusttunnel/credentials.toml` → содержит `[[client]]` блок с `username = "testuser@example.com"` и 64-символьным hex-паролем (SHA-256 от uuid)
- [ ] `systemctl is-active trusttunnel` → всё ещё `active` (сервис рестартанул при добавлении пользователя, ~1 с простой)
- [ ] `journalctl -u trusttunnel --no-pager -n 20` → нет ошибок после рестарта

---

## Шаг 3 — Генерация deep-link для тестового пользователя

```bash
# Через меню:
# Главное меню → 18 (TrustTunnel) → 5 (Сгенерировать deep-link)
# Email: testuser@example.com
```

**Альтернативно — через Python-REPL:**

```python
sudo python3 -c "
from chimera.modules.trusttunnel import trusttunnel_generate_deeplink
link = trusttunnel_generate_deeplink('testuser@example.com')
print(link)
"
```

**Проверки:**

- [ ] Вывод начинается с `tt://?` и содержит base64url-payload
- [ ] QR-helper URL `https://trusttunnel.org/qr.html#tt=...` напечатан ниже
- [ ] Deep-link декодируется (можно проверить локально):
  ```bash
  python3 -c "
  from chimera.modules.trusttunnel import trusttunnel_deeplink_decode
  d = trusttunnel_deeplink_decode('tt://?...')
  print(d)
  "
  ```
  → `hostname` = домен из шага 1, `username` = `testuser@example.com`, `password` = тот же hex что в `credentials.toml`, `addresses` = `["<домен>:8443"]`

---

## Шаг 4 — Подключение реальным клиентом

На тестовом устройстве:

1. Установить TrustTunnel-клиент из https://github.com/TrustTunnel/TrustTunnelClient (iOS App Store / Google Play / macOS DMG).
2. Открыть клиент, выбрать "Добавить сервер" → "Импорт по ссылке/QR".
3. Вставить deep-link из шага 3 ИЛИ отсканировать QR-код со страницы `https://trusttunnel.org/qr.html#tt=...`.
4. Нажать "Подключиться".

**Проверки:**

- [ ] Клиент показывает статус "Подключено" в течение 5–10 секунд
- [ ] На VPS: `curl -s http://127.0.0.1:1987/metrics | grep client_sessions` → `client_sessions{protocol_type="http2"} 1` (или `http3` если клиент использует HTTP/3)
- [ ] На VPS: `curl -s http://127.0.0.1:1987/metrics | grep inbound_traffic_bytes` → значение начинает расти (клиент качает через туннель)
- [ ] На тестовом устройстве: открыть браузер, посетить `https://ifconfig.me` → должен показать IP тестового VPS, а не реальный IP устройства
- [ ] На тестовом устройстве: `curl https://1.1.1.1/cdn-cgi/trace` → `ip=` должен показать IP VPS

---

## Шаг 5 — Проверка трафика в /metrics

Пока клиент активно использует туннель (стриминг видео, скачивание файла):

```bash
# На VPS, несколько раз с интервалом 5 сек:
watch -n 5 'curl -s http://127.0.0.1:1987/metrics | grep -E "client_sessions|inbound_traffic|outbound_traffic"'
```

**Проверки:**

- [ ] `client_sessions{protocol_type="http2"}` (или `http3`) держится на 1 или больше всё время активной сессии
- [ ] `inbound_traffic_bytes` (клиент → endpoint) монотонно растёт
- [ ] `outbound_traffic_bytes` (endpoint → клиент) монотонно растёт
- [ ] После `systemctl restart trusttunnel` счётчики сбрасываются в 0 (это известное поведение — `traffic_accounting` компенсирует через baseline-offset, см. `trusttunnel_stats.py`)

---

## Шаг 6 — Проверка батчинга рестартов (опционально, для уверенности)

Если хотите убедиться, что `batch_context()` реально батчит рестарты при массовых операциях:

```python
sudo python3 -c "
import time
from chimera.modules import user_lifecycle
from unittest.mock import patch

# Мокаем restart чтобы считать вызовы
calls = []
def mock_restart():
    calls.append(time.time())
    return True

with patch('chimera.modules.trusttunnel.trusttunnel_restart_service',
           side_effect=mock_restart):
    with user_lifecycle.batch_context():
        for i in range(5):
            user_lifecycle.block_user(
                f'user{i}@example.com',
                reason='test_batching',
                protocols=['trusttunnel'],
            )

print(f'Restarts called: {len(calls)} (expected: 1)')
print(f'Timestamps: {calls}')
"
```

**Ожидаемый результат:** `Restarts called: 1` — все 5 блокировок сгруппированы в один рестарт.

---

## Шаг 7 — Удаление TrustTunnel

```bash
# Через меню:
# Главное меню → 18 (TrustTunnel) → 8 (Удалить) → подтвердить "yes"
```

**Проверки после удаления:**

- [ ] `systemctl is-active trusttunnel` → `inactive` или `unknown`
- [ ] `systemctl is-enabled trusttunnel` → `disabled` или `unknown`
- [ ] `ls /etc/systemd/system/trusttunnel.service` → файл не существует
- [ ] `ls /opt/trusttunnel/` → директория не существует
- [ ] `ls /etc/cron.d/trusttunnel` → файл не существует (cron-задачи убраны)
- [ ] `ls /etc/letsencrypt/renewal-hooks/deploy/trusttunnel-reload.sh` → файл не существует
- [ ] `ufw status | grep 8443` → порты 8443/tcp и 8443/udp НЕ в списке (правила убраны)
- [ ] `cat /var/lib/xray-installer/trusttunnel.json` → файл не существует (state очищен)
- [ ] Остальные протоколы (VLESS, AWG, Hysteria2 и т.д.) продолжают работать: `systemctl is-active xray` → `active`, `systemctl is-active nginx` → `active`

---

## Что делать, если что-то пошло не так

### Сервис не стартует

```bash
journalctl -u trusttunnel --no-pager -n 50
# Частые причины:
#   - порт 8443 занят другим процессом: ss -tlnp | grep 8443
#   - сертификат не получен: ls /etc/letsencrypt/live/<домен>/
#   - неверный формат vpn.toml: cat /opt/trusttunnel/vpn.toml
```

### Deep-link не импортируется клиентом

```bash
# Проверить, что deep-link декодируется нашим pure-Python кодеком:
python3 -c "
from chimera.modules.trusttunnel import trusttunnel_deeplink_decode
d = trusttunnel_deeplink_decode('tt://?...')
print(d)
"
# Если декодируется — проблема в клиенте (проверить версию TrustTunnel-клиента)
# Если не декодируется — проблема в нашем кодеке, сравнить с upstream scripts/deeplink_to_config.py
```

### Клиент подключается, но трафик не идёт

```bash
# Проверить, что ufw не блокирует:
ufw status numbered | grep -E "8443|1987"

# Проверить, что endpoint реально слушает:
ss -tlnp | grep 8443
ss -ulnp | grep 8443

# Проверить /metrics — растут ли счётчики:
curl -s http://127.0.0.1:1987/metrics | grep traffic
```

### После удаления остались висячие cron-задачи

```bash
# Должно быть пусто:
ls /etc/cron.d/ | grep trusttunnel
# Если нет — удалить вручную:
sudo rm /etc/cron.d/trusttunnel
```

---

## Чеклист готовности к production

После прохождения всех шагов выше:

- [ ] Handshake работает стабильно (10+ переподключений без ошибок)
- [ ] Трафик считается в `/metrics` (агрегированно — per-user не поддерживается, см. `TROUBLESHOOTING.md`)
- [ ] `--trusttunnel-health` cron отрабатывает без ошибок (проверить `/var/lib/xray-installer/trusttunnel-health.status` через 10 минут)
- [ ] `--trusttunnel-stats` cron записывает агрегированный трафик (проверить `traffic_accounting.json` через 10 минут — должна появиться запись `"trusttunnel": {"_aggregate": {...}}`)
- [ | Удаление отрабатывает чисто (все проверки из Шага 7)
- [ ] Остальные протоколы проекта не затронуты (регрессионный smoke-test проходит)

Если все пункты отмечены — интеграция готова к production-использованию.
