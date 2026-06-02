# Hysteria2 Transport — VLESS Ultimate Installer

## Обзор

Hysteria2 добавлен как **альтернативный транспортный уровень** для Режима B
(Entry → Exit → Internet). Клиенты подключаются по обычным VLESS-ссылкам
и не замечают смены транспорта.

```
Клиент  ──VLESS──►  Entry VPS  ──Hysteria2/QUIC/UDP──►  Exit VPS  ──►  Интернет
         (обычная ссылка)       (скрытый транспорт)
```

AWG и Hysteria2 работают параллельно. Транспорт переключается через меню
или CLI без переустановки.

---

## Быстрый старт

### 1. Миграция с AWG (рекомендуется)
```bash
sudo python3 migrate_awg_to_h2.py --install-exit
```

### 2. Чистая установка через меню
```bash
sudo python3 main.py
# → Hysteria2 транспорт → Exit-нода → Установить
```

### 3. CLI
```bash
# Установить H2 на локальную Exit-ноду
sudo python3 main.py --h2-install-exit --h2-port 443

# Установить на нескольких портах
sudo python3 main.py --h2-install-exit --h2-port 443,8443

# Переключить транспорт
sudo python3 main.py --h2-transport h2
sudo python3 main.py --h2-transport awg

# Smoke Test
sudo python3 main.py --h2-smoke

# Статус
sudo python3 main.py --h2-status
```

---

## Модули

| Файл | Назначение |
|---|---|
| `hysteria2_common.py` | Общие утилиты, state.json helpers, TG, iptables |
| `hysteria2_exit_mgr.py` | Установка H2 сервера (локально и удалённо по SSH) |
| `hysteria2_transport.py` | Патч Xray outbound на Entry-ноде |
| `hysteria2_health.py` | QUIC-пинг, RTT, потери (не TCP) |
| `hysteria2_balancer.py` | weightedRandom/leastRtt/roundRobin |
| `hysteria2_watchdog.py` | Авторестарт через cron (каждые 2 мин) |
| `hysteria2_traffic.py` | Статистика iptables/ip6tables/ss без новых демонов |
| `hysteria2_cert_mgr.py` | TLS: certbot + self-signed, мониторинг срока |
| `hysteria2_auto_update.py` | Автообновление бинарника с GitHub Releases |
| `hysteria2_cluster.py` | SSH-операции на группе Exit-нод |
| `hysteria2_backup.py` | Бэкап конфигов, миграция AWG→H2 |
| `hysteria2_smoke_test.py` | Полная проверка после apply |
| `hysteria2_dpi.py` | Тест блокировки QUIC/UDP, авто-фолбэк порта |
| `hysteria2_quality.py` | RTT/потери/скорость + TG-отчёт + авто-оптимизация |
| `hysteria2_menu.py` | Главное интерактивное меню |

---

## Интеграция в _core.py (аддитивно)

В `_core.py` добавляется **только импорт и вызов**. Никаких изменений
существующих функций:

```python
# В блоке импортов:
from vless_installer.modules.hysteria2_menu import do_hysteria2_menu

# В main_menu() — новый пункт 7:
elif choice == "7":
    do_hysteria2_menu()

# В _menu_network() — новый пункт H:
elif ch.lower() == "h":
    do_hysteria2_menu()
```

---

## Порты и IPv6 / DualStack

### Поддержка портов
- Один порт: `--h2-port 443`
- Несколько: `--h2-port 443,8443,2083`
- Port hopping: через конфиг Hysteria2 (диапазон `443-8443`)
- Fallback при блокировке DPI: автоматически через `hysteria2_dpi.py`

### DualStack (IPv4 + IPv6)
- Автодетект IPv6 при установке
- Отдельные правила iptables и ip6tables
- Health Check корректно работает с IPv6-адресами `[2001:db8::1]:443`
- Балансировщик поддерживает раздельные веса для IPv4/IPv6 нод
- Сертификаты: certbot + IPv6 домены

### iptables/ip6tables
При добавлении порта автоматически:
```bash
iptables  -I INPUT -p udp --dport 443 -j ACCEPT
ip6tables -I INPUT -p udp --dport 443 -j ACCEPT
```

---

## Cron-задачи (устанавливаются через меню)

| Файл cron | Интервал | Назначение |
|---|---|---|
| `/etc/cron.d/hysteria2-watchdog` | каждые 2 мин | авторестарт |
| `/etc/cron.d/hysteria2-autoupdate` | 1 раз в сутки (03:00) | обновление |
| `/etc/cron.d/hysteria2-cert-renew` | еженедельно (пн 08:00) | мониторинг сертификата |

---

## CLI-флаги

```
--h2-install-exit      Установить H2 на Exit-ноду
--h2-port <ports>      UDP-порт(ы), например: 443 или 443,8443
--h2-transport <awg|h2> Переключить транспорт
--h2-weights <ip:w,..>  Задать веса нод
--h2-status            Статус JSON
--h2-health            Health check (cron)
--h2-traffic           Отчёт по трафику
--h2-quality-report    Отчёт качества [--tg]
--h2-logs              Хвосты логов H2
--h2-cluster <op>      Кластер: status|restart|logs|update
--h2-cert              (интерактивно)
--h2-smoke             Smoke test
--h2-autoupdate        Автообновление (cron)
--h2-watchdog-run      Watchdog (cron)
--h2-cert-monitor      Мониторинг сертификата (cron)
--h2-dpi-check         DPI авто-фолбэк (cron)
```

---

## state.json — секция hysteria2

Пример: `hysteria2_state_example.json`

Ключевые поля:
- `enabled` — H2 установлен и активен
- `active_transport` — текущий транспорт (`awg`/`hysteria2`)
- `exit_nodes[]` — список нод с IP, портами, паролем, метриками
- `firewall.udp_ports` — активные UDP-порты
- `firewall.fallback_ports` — кандидаты при DPI-блокировке
- `balancer.strategy` — `weightedRandom`/`leastRtt`/`roundRobin`
- `health_check.method` — всегда `quic_ping`

---

## Zero-Breakage гарантии

- VLESS/xHTTP TLS режимы — **не затронуты**
- AWG и все режимы установки — **работают штатно**
- Генерация VLESS-ссылок — **не изменена**
- Существующие CLI-флаги — **не изменены**
- Все изменения — **только аддитивны** (новые файлы, новые функции, новые ключи state.json)
