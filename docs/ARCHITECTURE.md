# Архитектура Chimera — компоненты, Telemt, хранение состояния

> Секции README.md («Компоненты», «Telemt MTProto — интеграция с xray-каскадом»,
> «Хранение состояния»), вынесенные миграцией 2026-10-29. Режимы развёртывания
> (A/B/Multi) остаются в README. Текст не менялся.

### Компоненты

```
┌─────────────────────────────────────────────────────────────┐
│                        Chimera Project                      │
│                                                             │
│  bootstrap.sh ──► main.py ──exec──► _core.py                │
│                                         │                   │
│                               modules/            │
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
