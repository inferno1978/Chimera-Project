# Chimera Project v5.0.0

[![Version](https://img.shields.io/badge/version-5.0.0-blue.svg)](https://github.com/inferno1978/Chimera-Project)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](https://github.com/inferno1978/Chimera-Project/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)](https://ubuntu.com)

**Multi-Protocol Anti-DPI Installer** — мульти-протокольный установщик для обхода цензуры: VLESS REALITY/xHTTP, Hysteria2, AmneziaWG, TrustTunnel, MTProto, NaiveProxy, Mieru, FPTN, Slipgate и др. Полная автоматизация: от установки до мониторинга, с кластеризацией, балансировкой, веб-панелью и REST API.

> **Почему Chimera?** Проект вырос из простого VLESS-installer в мульти-протокольный комбайн: 9+ протоколов, 143 модуля, 25 категорий — как мифическая химера, собранная из частей разных животных. Каждая «голова» (протокол) нужна для своего сценария: VLESS — основной, AmneziaWG — устойчивый к DPI, Hysteria2 — быстрый UDP, TrustTunnel — AdGuard VPN protocol, и т.д. Если цензор блокирует один протокол, химера «выращивает новую голову». Подробное обоснование — в CHANGELOG v5.0.0.

```
 ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
 Chimera Project v5.0.0 — Multi-Protocol Anti-DPI Installer
```

## ⚡ Быстрый старт

```bash
bash <(curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh)
```

Или с `wget`:

```bash
wget -O bootstrap.sh https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/bootstrap.sh
chmod +x bootstrap.sh
bash bootstrap.sh
```

> **Note:** Репозиторий также доступен на GitHub: `github.com/inferno1978/Chimera-Project` (ветка `main`). GitLab-зеркало (ветка `chimera-v5`) — основной источник для `curl | bash`.

## 🎯 Возможности

| Категория        | Функции                                                              |
| ---------------- | -------------------------------------------------------------------- |
| **Протоколы**    | VLESS + TCP + REALITY, VLESS + xHTTP + TLS, TrustTunnel (AdGuard VPN) |
| **Режимы**       | Одиночный (A), Каскад Россия→Зарубеж (B), Мульти-каскад (до 10 нод) |
| **Транспорт**    | AmneziaWG (AWG 2.0) с multi-node балансировкой                       |
| **Маскировка**   | XTLS Vision/Splice, сайты-заглушки (TechHub, Nextcloud, custom)      |
| **DNS**          | DNSCrypt-proxy, кастомные DNS-правила, DNS Leak Test                 |
| **Анти-цензура** | Split Tunneling, РФ-подсети (RIPE NCC), AS-direct routing            |
| **CloudFlare**   | WARP full / selective / runet-only                                   |
| **Безопасность** | AutoBan, DPI Detector, Honeypot, SSH Hardening                       |
| **Мониторинг**   | Smart Balancer, Watchdog, Health Reports, Failover A↔B               |
| **Пользователи** | Добавление/удаление, QR-коды, ссылки, TTL, лимиты трафика            |
| **Диагностика**  | Health Check, MTU Tracepath, Speed Test, TLS Cert Check              |
| **Интеграции**   | Telegram-уведомления, Clash Meta / Sing-box конфиги                  |
| **Обслуживание** | Авторестарт, автообновление xray/geo, миграция конфигов              |
| **v4.11.1**        | Smoke-test, nginx Watchdog `[NW]`, ipset Persist `[IP]`, Кластер `[CL]` |
| **v4.11.4**        | Telemt MTProto на entry-ноде → xray-каскад → Telegram (VLESS / AWG 2.0) |
| **v4.11.5**        | TCP-фрагментация ClientHello: обход DPI, 6 модулей, поддержка Happ / Incy / Nekoray |
| **v4.12.3** 🔥 | Hysteria2 транспорт: меню 7, выбор H2 при установке Режима B, балансировщик нод |
| **v4.12.8**        | Интерактивный выбор TLS Fingerprint (11 вариантов) при установке и для каждой exit-ноды; единый модуль `fingerprint_manager.py`; FP сохраняется в state.json и применяется во всех режимах (A, B, AWG, WARP) |
| **v4.12.8** 🛡️ | Telemt MSS-фрагментация против TSPU JA4 DPI: новый модуль `telemt_mss_selector.py`, 10 пресетов (tspu★/2in8/extreme-low/…) с интерактивным выбором при установке Telemt |
| **v4.12.9** 📊 | Статистика трафика NaiveProxy и Mieru: новые модули `naiveproxy_stats.py` и `mieru_stats.py`; метрики из iptables, journalctl, ss; гистограммы активности, топ клиентов, NTP-мониторинг; живое обновление каждые 30 сек |
| **v4.13** 🚀 | Полный рефакторинг кодовой базы; добавлены Web Admin Panel, User Portal и REST API |
| **v4.14** 🔒 | AmneziaWG 2.0 standalone VPN: 13 новых модулей `awg_*.py` (полный порт bivlked/amneziawg-installer), 9 carrier-пресетов (Yota/Tele2/Мегафон/Билайн/T-Mobile US), каскад RU→зарубеж с split-routing, QR+`vpn://` URI, временные клиенты, backup/restore, diagnose с carrier-compare |
| **v4.15 NEW** 🛡️ | AmneziaWG peer management в веб-панели: новый модуль `awg_rest_api.py` (15 REST endpoints), `owner_email` model (admin видит все пиры, user — только свой), Admin Panel — секция AmneziaWG с CRUD, User Portal — карточка «Мой AmneziaWG» (QR/conf/regen). Security: PSK фильтрация из JSON, QR PNG chmod 0o600, нет print ключа в journal. Bug fixes: порядок nginx→сокет, state.json ДО health check. |
| **v4.20.1** 🎭 | Telemt nginx-fallback: режим "own-site" — свой домен + свой сайт на локальном nginx вместо чужого donor-домена. Telemt сплайсит failed handshakes на локальный nginx с реальным Let's Encrypt сертификатом (`censorship.mask_host` + `tls_emulation=true`), убирая детектируемую аномалию `fake_cert_len=2048`. Рефакторинг сигнатур `create_website()` / `setup_nginx_final()` / `obtain_ssl_cert()` — опциональные `domain`/`port`/`socket_path` перекрывают `core.PARAM_*` без мутации глобального state. Guard перед стартом Telemt: проверка готовности nginx (TCP connect) — откат к donor-режиму если nginx не слушает (защита от silent regression в духе AWG rotation no-op, telemt/telemt #330 #713). 24 новых регресс-теста. |

## 🔐 TrustTunnel (AdGuard VPN protocol)

**Меню:** главное → `18` · **Upstream:** https://github.com/TrustTunnel/TrustTunnel

Референсная реализация протокола AdGuard VPN на Rust (Apache 2.0, open-source с января 2026). Интеграция использует **официальный upstream-бинарник** `trusttunnel_endpoint` + `setup_wizard` (prebuilt, GPG-подписан ключом AdGuard `28645AC9...`) — НЕ форк и НЕ реимплементация. Транспорт: HTTP/2-over-TLS (TCP) и HTTP/3-over-QUIC (UDP) с мультиплексированием TCP/UDP/ICMP. Выдача доступа пользователю — через deep-link `tt://?<base64url>` (upstream TLV-формат), который встраивается в существующий self-service Telegram-бот наравне с `vless://`, `vpn://`, `hysteria2://`.

**Порт по умолчанию: `8443` (TCP + UDP).** Это отдельный порт, не 443 — порт 443 уже занят VLESS (TCP, REALITY или xHTTP) и Hysteria2 (UDP), а TrustTunnel слушает одновременно TCP и UDP на одном номере порта, не имеет SNI-dispatch и не умеет fallback. При установке конфликт проверяется через `core.check_port_used_by_other_protocol`.

Сертификаты — через существующий конвейер `ssl_certbot.obtain_ssl_cert()`, feed в `setup_wizard --cert-type provided`. Авто-renewal — через certbot cron + deploy-hook `systemctl reload trusttunnel` (SIGHUP перезагружает `hosts.toml` без рестарта, без разрыва активных сессий).

Управление пользователями — общий `user_lifecycle.TrustTunnelAdapter`, credentials в `/opt/trusttunnel/credentials.toml` (TOML, массив `[[client]]`). Известные ограничения — см. [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) (агрегированный трафик, рестарт при смене пользователей).

## 📋 Требования

| Параметр | Минимум          | Рекомендуется            |
| -------- | ---------------- | ------------------------ |
| ОС       | Ubuntu 20.04 LTS | Ubuntu 22.04 / 24.04 LTS |
| Python   | 3.10+            | 3.12                     |
| RAM      | 512 МБ           | 1 ГБ+                    |
| Права    | root             | root                     |
| Сеть     | Публичный IP     | Публичный IP + домен     |

**Поддерживаемые ОС:** Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12 / 13

## 🔧 Ручная установка

```bash
git clone https://github.com/inferno1978/Chimera-Project /opt/chimera
cd /opt/chimera
sudo python3 main.py
```

## 🗂️ Структура проекта

```text
Chimera-Project/
├── main.py                      # Точка входа
├── bootstrap.sh                 # Установка одной командой
├── verify.py                    # Проверка целостности (232 теста, ~10/10)
├── full_test.py                 # Полный автотест (10 секций)
├── smoke_test_modules.py        # 42 smoke-теста в стен-режиме
├── README.md / INSTALL.md / CHANGELOG.md / TROUBLESHOOTING.md
├── PROJECT_MAP.md               # Полная карта 143 модулей по 25 категориям
├── SECURITY.md / CONTRIBUTING.md / INTEGRATION.md / HYSTERIA2.md
├── LICENSE
└── chimera/
    ├── __init__.py
    ├── _core.py                 # Ядро: orchestrator + globals (~8 093 строк, −75% от 32 557)
    ├── __all_exports.py         # Реестр экспортируемых имён
    └── modules/                 # 143 модуля по 25 категориям (см. PROJECT_MAP.md)
        │
        ├── 1. Ядро и утилиты
        │   └── box_renderer, resources, system_deps, tui, scheduler, smoke_test, xray_safe_apply
        │
        ├── 2. Установка и конфиг Xray
        │   └── xray_install, install_prompts, nginx_setup, ssl_certbot, network_setup, dnscrypt_setup/selector, geo_files, backup_rollback, emergency_repair, uninstall
        │
        ├── 3. Пользователи и доступ
        │   └── users_manager, ttl_users, credential_rotation, user_fp_manager, fingerprint_manager, subscription
        │
        ├── 4. Маршрутизация и split-tunnel
        │   └── split_tunnel, ru_subnets, as_direct, geoip_block, dns_rules, ingress_geoip, ripe_file_age
        │
        ├── 5. Безопасность и баны
        │   └── autoban, fail2ban_setup/manager, ipban, ipset_persist, ssh_hardening, honeypot
        │
        ├── 6. Мониторинг и диагностика
        │   └── diagnostics, connection_audit, health, health_report, traffic_tracking, traffic_history, node_health_monitor, network_bench, status_panel, standalone_screens
        │
        ├── 7. Статус, скорость, реконфигурация
        │   └── quick_status, speed_test, reconfigure, switch_mode, migration, cold_boot_restore, config_backup
        │
        ├── 8. Telegram и уведомления
        │   └── tg_bot, tg_nets
        │
        ├── 9. Фрагментация (TLS fragmentation)
        │   └── fragment_config/fuzzer/log_viewer/presets/link/guide/share/stats/mux/noise/watchdog (11 мод.)
        │
        ├── 10. Hysteria2 (15 модулей)
        │   └── hysteria2_common/menu/transport/cert_mgr/balancer/cluster/dpi/exit_mgr/health/quality/smoke_test/traffic/watchdog/backup/auto_update
        │
        ├── 11. Альтернативные протоколы
        │   └── mtproto(+_stats), naiveproxy(+_stats), mieru(+_stats), fptn, olcrtc, wdtt, webdav_tunnel, turnable, turntunnel(+_links), vkturn_menu, port_hopping, proto_common
        │
        ├── 12. WARP и зеркала
        │   └── warp, warp_curated_lists, entry_mirrors, slipgate
        │
        ├── 13. Кластер и балансировка
        │   └── cluster_ops, smart_balancer, failover, chain_nodes
        │
        ├── 14. Telemt (телеметрия)
        │   └── telemt_panel/fallback/ios_fix/mss_selector/syn_limiter/self_route/warp_route
        │
        ├── 15. DPI-детекторы
        │   └── dpi_detector, dpi_censor_check
        │
        ├── 16. Клиентские конфиги и MTU
        │   └── client_config_export, pq_vless, mtu_tuning, asn_cache
        │
        ├── 17. Веб-панель, Admin, Portal
        │   └── rest_api, admin_panel, user_portal, awg_rest_api
        │
        ├── 18. AWG Transport (Mode B)
        │   └── awg_transport (45 функций)
        │
        └── 19. Вендорные модули
            └── _vendor/dpi_detector/ (Python)

        ── 20. AmneziaWG 2.0 standalone (14 модулей + awg_net_common, NEW v4.15.0) ──
           awg_constants/state/presets/hw_tuning/apply/standalone/
           peers/qr/expires/backup/cascade/diagnose/uninstall/
           net_common (общий NAT/sysctl слой) + awg_rest_api (REST API для веб-панели)
           — полный порт bivlked/amneziawg-installer, carrier-пресеты, каскад,
             управление пирами через Admin Panel + User Portal
```

> 📋 **Полная карта по 25 категориям** с описанием каждого файла — в [`PROJECT_MAP.md`](PROJECT_MAP.md).

## 🏗️ Архитектура

### Режимы развёртывания

**Режим A — одиночный сервер**

```
Клиент ──VLESS/REALITY──► VPS (любая страна) ──► Интернет
```

**Режим B — каскад Россия → Зарубеж**

```
Клиент ──VLESS/REALITY──► Entry VPS (RU) ──AWG──► Exit VPS (EU/US) ──► Интернет
```

**Режим B Multi — мульти-каскад с балансировкой**

```
                              ┌──► Exit VPS 1 (EU) ──►┐
Клиент ──► Entry VPS (RU) ─── ┼──► Exit VPS 2 (US) ──►├──► Интернет
                              └──► Exit VPS 3 (AS) ──►┘
```

### Компоненты

```
┌─────────────────────────────────────────────────────────────┐
│                        Chimera Project                      │
│                                                             │
│  bootstrap.sh ──► main.py ──exec──► _core.py                │
│                                         │                   │
│                               modules/ (v5.0.0)           │
│                                         │                   │
│         Xray-core              Nginx (TLS)                  │
│         /etc/xray/             /etc/nginx/                  │
│         config.json            sites-enabled/               │
│              │                      │                       │
│         iptables/ipset         Certbot (ACME)               │
│         (ingress block)                                     │
│              │                                              │
│         AmneziaWG (AWG)                                     │
│         /etc/amnezia/awg0.conf                              │
└─────────────────────────────────────────────────────────────┘
```

| Компонент            | Роль                                            |
| -------------------- | ----------------------------------------------- |
| **Xray-core**        | VLESS REALITY / xHTTP TLS, routing, outbounds   |
| **Nginx**            | TLS termination, маскировочный сайт-заглушка    |
| **AmneziaWG**        | Зашифрованный туннель Entry→Exit (Режим B)      |
| **DNSCrypt-proxy**   | Зашифрованный DNS, защита от leak               |
| **ipset + iptables** | Ingress-блокировка РФ подсетей (опционально)    |
| **Certbot**          | TLS-сертификаты Let's Encrypt (xHTTP режим)     |

### Telemt MTProto — интеграция с xray-каскадом `[v4.12.1]`

Для entry-нод в России: Telemt принимает клиентов по MTProto,
трафик перехватывается через `iptables REDIRECT` и направляется
в `dokodemo-door` inbound xray, затем уходит через каскад на exit VPS.

```
Клиент (Telegram)
    │  tg://proxy?server=ENTRY_IP...
    ▼
Telemt (entry VPS / RU)  — type = "direct"
    │  iptables REDIRECT  →  127.0.0.1:10811
    ▼
Xray dokodemo-door  (tag: tproxy-telemt)
    │  routing: inboundTag → balancerTag / outboundTag
    ▼
┌─ VLESS+REALITY:  chain-exit[-1] → exit VPS
└─ AWG 2.0:        fwmark → awg0  → exit VPS
    ▼
Серверы Telegram ✓
```

### Хранение состояния

```
/etc/xray/
├── config.json              # Конфиг Xray
├── ru_subnets_ripe.txt      # РФ подсети (split tunneling)
├── geosite.dat / geoip.dat  # GeoData (runetfreedom)
└── config.json.pre-apply    # Авто-бэкап перед каждым apply

/var/lib/xray-installer/
├── state.json               # Состояние установщика (UUID, ключи, настройки)
├── ingress_geoip.json       # Состояние ingress-блокировки
└── backups/                 # Резервные копии конфигов

/etc/ipset.conf              # [v4.12.1] Дамп ipset для восстановления при reboot
/var/log/
├── vless-install.log        # Лог установщика
├── nginx-watchdog.log       # [v4.12.1] Лог nginx watchdog
└── xray-ipset-restore.log   # [v4.12.1] Лог восстановления ipset
```

## 🖥️ Управление сервисами

```bash
systemctl status xray nginx
systemctl restart xray nginx
journalctl -u xray -f
```

## 🖥️ CLI-флаги

```bash
sudo python3 /opt/chimera/main.py                   # Меню
sudo python3 /opt/chimera/main.py --status          # Быстрый статус
sudo python3 /opt/chimera/main.py --scheduled-backup
sudo python3 /opt/chimera/main.py --switch-mode-a
sudo python3 /opt/chimera/main.py --switch-mode-b
sudo python3 /opt/chimera/main.py --autoban
sudo python3 /opt/chimera/main.py --ttl-check
sudo python3 /opt/chimera/main.py --smart-balance
sudo python3 /opt/chimera/main.py --dpi-check
sudo python3 /opt/chimera/main.py --update-ru-subnets
sudo python3 /opt/chimera/main.py --update-as-direct
sudo python3 /opt/chimera/main.py --ingress-geoip-update
sudo python3 /opt/chimera/main.py --telemt-panel-geoip-update   # DB-IP Lite, без MaxMind-аккаунта; --maxmind — зеркало GeoLite2
sudo python3 /opt/chimera/main.py --pinned-fallback-check
sudo python3 /opt/chimera/main.py --tg-event EVENT MSG
sudo python3 /opt/chimera/main.py --clear-asn-cache
```

## 🔗 Кластерное управление `[CL]`

Меню **Безопасность и Автоматизация → `[CL]`** позволяет управлять всеми
Exit Nodes из Entry Node одной командой по SSH.

| Пункт | Действие |
|-------|----------|
| `1` | Диагностика всех нод (статус + xray -test) |
| `2` | Перезапуск Xray на всех нодах |
| `3` | Обновление Xray-core на всех нодах |
| `4` | Ротация UUID на всех нодах |
| `5` | Произвольная команда на всех нодах |
| `6` | Проверить SSH-доступ к нодам |
| `P` | Задать / сменить пароль SSH-сессии |

**Аутентификация:** сначала пробуется SSH-ключ (`~/.ssh/id_ed25519` и др.),
при неудаче — запрашивается пароль root (один раз за сессию через `sshpass`).

> **Зависимость:** для парольной аутентификации требуется `sshpass`
> (`apt install sshpass`). При первом использовании устанавливается автоматически.

## 🔍 Диагностика

```bash
# Полная диагностика через меню
sudo python3 /opt/chimera/main.py
# → Диагностика и Мониторинг → Полная диагностика

sudo python3 /opt/chimera/main.py --status
/usr/local/bin/xray run -test -config /etc/xray/config.json
tail -100 /var/log/chimera.log
```

## 🔄 Обслуживание

```bash
python3 /opt/chimera/verify.py
cd /opt/chimera && git pull
sudo python3 /opt/chimera/main.py --scheduled-backup
```

## ❓ Решение проблем

Смотри [TROUBLESHOOTING.md](https://github.com/inferno1978/Chimera-Project/blob/main/TROUBLESHOOTING.md).

## 📌 О проекте и формате общения

> **Этот проект — личная инициатива, разрабатывается и поддерживается в свободное
> от основной занятости время. Это не коммерческий продукт и не услуга с SLA.**
>
> **Что это значит на практике:**
>
> - Автор не обязан отвечать в каком-либо конкретном темпе, реализовывать
>   любую функцию по запросу или подстраивать архитектуру под чужие сценарии.
> - Сообщения в требовательном или претензионном тоне будут проигнорированы.
>   Токсичное поведение — повод для бана без предупреждения.
>
> **Как помочь проекту или получить помощь:**
>
> - Нашли реальный баг? Опишите шаги воспроизведения — это самое полезное,
>   что можно сделать.
> - Есть идея фичи? Аргументированное предложение с пользой для проекта
>   в целом — welcome.
> - Хотите другую логику под свои задачи? Форкайте репозиторий и меняйте
>   как нужно — для этого он open-source.
>
> **Спасибо всем, кто использует проект с уважением к тому, что он создан
> бесплатно и на энтузиазме.**

## 🔗 Связанные проекты

- [HYDRA-ULTIMATE](https://github.com/gr33nimax/HYDRA-ULTIMATE) — форк на базе Sing-Box как единого оркестратора трафика, с плагинной архитектурой и собственным набором транспортов.

## 📄 Лицензия

MIT — см. [LICENSE](https://github.com/inferno1978/Chimera-Project/blob/main/LICENSE)

## ✍️ Автор

inferno1978 · [GitHub](https://github.com/inferno1978)
