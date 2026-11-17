# SmartDNS — FAQ по DoH/DoT stealth-ноде и прозрачному SNI-прокси

Полное руководство по SmartDNS-ноде — публичному DNS-резолверу со
стелс-маскировкой под обычный сайт и прозрачному SNI-прокси для заблокированных
ресурсов. Охватывает оба режима развёртывания (standalone / companion),
установку через визард и CLI, взаимодействие со стеком Chimera, файрвол,
авторизацию клиентов, обновления, диагностику и удаление.

> **SmartDNS-нода** — стек из четырёх компонентов (xray + nginx + DNS-движок
> OxiDNS/AdGuardHome + acme.sh), который разворачивает на VPS личный
> DoH/DoT-резолвер, замаскированный под обычный сайт-визитку: DoH прячется в
> корне собственного домена по секретному пути, DoT слушает 853/TLS, а
> заблокированные домены из списка GeoHideDNS резолвятся движком в адрес самой
> ноды и прозрачно проксируются через SNI-прокси xray — авторизованные клиенты
> открывают заблокированные сайты без VPN-клиента вовсе.
>
> Python-порт bash-установщика `smartdns-installer` v2.10.0-stealth (5594
> строк), влит в Chimera как v3.0.0 по образцу модуля B4 (dpi_bypass.py).
> Исходный bash-репозиторий (заморожен, канонический код теперь в Chimera):
> https://github.com/EvgenyElizarenko/smartdns-installer
>
> Описано по коду стека v3.0.0 (коммит 17.11.2026): модули `smartdns.py` /
> `smartdns_stack.py` / `smartdns_firewall.py`.

---

## Оглавление

1. [Что такое SmartDNS-нода и зачем она нужна](#1-что-такое-smartdns-нода-и-зачем-она-нужна)
2. [Архитектура: как устроен стек](#2-архитектура-как-устроен-стек)
3. [Режимы: standalone и companion (и почему «общий IP» отвергнут)](#3-режимы-standalone-и-companion-и-почему-общий-ip-отвергнут)
4. [Установка через меню (визард по шагам)](#4-установка-через-меню-визард-по-шагам)
5. [Установка через CLI (флаги, non-interactive, exit-коды)](#5-установка-через-cli-флаги-non-interactive-exit-коды)
6. [Preflight — проверки перед установкой](#6-preflight--проверки-перед-установкой)
7. [Компоненты, версии и зеркала загрузок](#7-компоненты-версии-и-зеркала-загрузок)
8. [Xray: прозрачный SNI-прокси (8444/853)](#8-xray-прозрачный-sni-прокси-8444853)
9. [nginx: cover-site, DoH-эндпоинт, web-auth и DoT-терминатор](#9-nginx-cover-site-doh-эндпоинт-web-auth-и-dot-терминатор)
10. [DNS-движки: OxiDNS и AdGuardHome](#10-dns-движки-oxidns-и-adguardhome)
11. [GeoHide: спуфинг заблокированных доменов — полная петля](#11-geohide-спуфинг-заблокированных-доменов--полная-петля)
12. [Cloudflare и wildcard-сертификат](#12-cloudflare-и-wildcard-сертификат)
13. [Файрвол: iptables, ufw и companion-разводка](#13-файрвол-iptables-ufw-и-companion-разводка)
14. [Авторизация клиентов: ipset-whitelist и web-auth закладка](#14-авторизация-клиентов-ipset-whitelist-и-web-auth-закладка)
15. [Взаимодействие с Химерой (режим companion) — во всех деталях](#15-взаимодействие-с-химерой-режим-companion--во-всех-деталях)
16. [Обновление стека](#16-обновление-стека)
17. [Статус и диагностика](#17-статус-и-диагностика)
18. [Бэкап и откат](#18-бэкап-и-откат)
19. [Удаление](#19-удаление)
20. [Решение проблем](#20-решение-проблем)
21. [Приложение: сводные таблицы (порты, юниты, пути, CLI)](#21-приложение-сводные-таблицы-порты-юниты-пути-cli)

---

## 1. Что такое SmartDNS-нода и зачем она нужна

### Проблема: DNS-запросы как сигнал для цензора

Обычный рекурсивный DNS-сервер, поднятый «в лоб», бесполезен в условиях
российской цензуры по трём причинам:

- **Порт 53/UDP открыт в интернет** — это яркий маркер «публичный
  DNS-резолвер» для сканеров (Shodan/Censys) и первый кандидат на блокировку
  или абьюз. РКН и провайдеры активно душат чужие публичные резолверы.
- **DoH/DoT на стандартных признаках** — публичные DoH-сервисы (Cloudflare,
  Google, Quad9, NextDNS) блокируются по SNI/домену; собственный DoH-хост,
  торчащий голым сертификатом без сайта, выделяется в толпе и рано или поздно
  попадает под нож.
- **DNS без последствий для HTTPS не спасает** — если браузер получает
  честный IP заблокированного сайта, соединение всё равно рвётся по SNI.
  Разница «резолвим правильно, но подключиться не можем» не даёт пользователю
  ничего.

### Решение: резолвер, замаскированный под сайт, + SNI-прокси

SmartDNS-нода закрывает все три пункта одновременно:

| Проблема | Как решает SmartDNS-нода |
|---|---|
| Публичный 53 палится | Порт 53 наружу **не слушается вовсе**. DNS принимается только через DoH (443/TLS, секретный путь) и DoT (853/TLS). Plain-DNS движка живёт только на loopback 127.0.0.1:5353. |
| DoH-хост выделяется | На домене ноды висит **процедурно сгенерированный сайт-визитка** (студия/ателье: своя палитра, бренд, портфолио). DoH-эндпоинт спрятан в корне домена по секретному пути `/resolve/<52 случайных символа>`; любые «неправильные» запросы к этому пути получают **404 как у обычного сайта**. TLS-отпечаток — обычный nginx с LE-сертификатом, HSTS, полным набором security-заголовков. |
| Заблокированные сайты не открываются | **GeoHide-петля**: движок резолвит домены из списка GeoHideDNS в адрес самой ноды → клиент Connect'ится на 443 ноды → NAT-редирект в xray-докодемо → SNI-сниффинг → авторизованным клиентам трафик прозрачно проксируется к реальному сайту (freedom/direct), всем остальным отдаётся cover-site. **Клиент не устанавливает ничего** — заблокированный сайт просто «открывается». |

### Чем это отличается от остальных DNS-инструментов Chimera

| Инструмент | Для кого | Где живёт |
|---|---|---|
| AdGuard Home (AGH-стек, см. [AGH_FAQ.md](AGH_FAQ.md)) | DNS **для VPN-клиентов самой ноды** — фильтрация рекламы внутри туннеля | Loopback/внутренние порты, наружу не торчит |
| DNSCrypt-proxy (см. [DNSCRYPT_FAQ.md](DNSCRYPT_FAQ.md)) | Шифрованный **upstream** для резолвинга самой ноды + принудительный редирект | Loopback, клиент на ноде |
| Собственные DoH в сетах b4 (см. [OWN_DOH_FAQ.md](OWN_DOH_FAQ.md)) | Замена публичных DoH **в клиентских сетах b4** | Конфигурация b4 |
| **SmartDNS-нода** | **Публичный DNS-сервис для устройств без VPN-клиента**: телефон с Private DNS, роутер, ноутбук — достаточно указать DoT-хост или DoH-URL | Отдельный VPS (standalone) или второй IP на VPS с Химерой (companion) |

Ключевое отличие: AGH-стек обслуживает трафик, который **уже идёт через
туннель Химеры**. SmartDNS-нода — самостоятельный продукт: его клиенты
подключаются к нему напрямую, без VLESS/AWG/чего-либо ещё, и получают
(а) чистый резолв без цензуры и (б) прозрачный доступ к заблокированным
сайтам через SNI-прокси.

### Дополнительные свойства

- **Anti-fingerprint**: cover-site с X-Robots-Tag noindex, nofollow; HSTS
  max-age=63072000; скрытие Server/X-Powered-By на DoH-эндпоинте; ACME-ответы
  на 80-м порту не выделяются (см. аудит РКН-рекомендаций в
  docs/changelog/2026-11.md, запись fix(nginx-stub) от 16.11).
- **Абьюз-устойчивость**: DoT-порт 853 защищён hashlimit-лимитом 30
  соединений/мин на источник (с burst 40); DoH-эндпоинт — nginx limit_req
  200 r/s (burst 300); web-auth закладка — 30 r/s (burst 15).
- **Опциональный DoT-whitelist**: режим «853 открыт только для
  авторизованных IP» — авторизация одной закладкой в браузере на 24 часа
  (см. раздел 14).
- **Всё в экосистеме Chimera**: загрузки через download_manager (зеркала
  GitHub + gh-прокси), порты через port_registry, версии/обновления по
  паттерну B4 (авто-latest при установке, TTL-кэш, «доступно новое» в шапке
  меню), UI в фирменных боксах box_renderer.

### Происхождение и статус

Изначально — самостоятельный bash-установщик `smartdns-installer`
(v2.10.0-stealth, 5594 строк, репозиторий
`EvgenyElizarenko/smartdns-installer`). Решением владельца от 17.11.2026
переписан на Python и влит в Chimera как стек v3.0.0 тремя модулями
(`smartdns.py`, `smartdns_stack.py`, `smartdns_firewall.py`) — с
одновременным объединением режимов установки (см. раздел 3). Bash-репозиторий
на GitHub заморожен как есть (push-токена нет); канонический код — здесь.
Паритет логики с bash сохранён (конфиги, порты, правила файрвола, GeoHide-
конвейер), пути и имена юнитов неймспейснуты под v3.

---

## 2. Архитектура: как устроен стек

### Общая схема

```
                        ┌────────────────────────── VPS ноды SmartDNS ──────────────────────────┐
                        │                                                                        │
  DoH-клиент ──443/TLS──►  NAT PREROUTING (REDIRECT)                                               │
  (браузер/ОС)           │    ├─ источник в ipset smartdns_clients ──► :8444 (xray stealth DoH) │
                        │    └─ все прочие ────────────────────────► :9443 (nginx cover TLS)    │
                        │                                              │                          │
                        │   :9443 nginx «Unified Stealth Server»:      │                          │
                        │     /                    → cover-site (сайт-визитка)                    │
                        │     /resolve/<SECRET>   → 127.0.0.1:8053 движок DoH  ◄──┘              │
                        │     /auth/<SECRET>     → «Session Synchronized» + строка в auth.log    │
                        │                                                                        │
  DoT-клиент ──853/TLS──►  xray dokodemo dot-in (SNI-снифф)                                          │
  (Private DNS)          │    ├─ SNI = DOT_HOST → 127.0.0.1:8853 nginx stream (TLS-терминатор)   │
                        │    │                     └─► 127.0.0.1:5353 движок plain DNS           │
                        │    └─ прочий SNI ──────► block (blackhole)                                │
                        │                                                                        │
  GeoHide-петля:         │  движок резолвит <заблокированный домен> → SERVER_IP (hosts smart_a)   │
  (заблок. сайт)         │  клиент ──► 443 SERVER_IP → NAT → :8444 xray (SNI-снифф)               │
                        │    ├─ SNI из GeoHide-списка → freedom direct-v4 → реальный сайт        │
                        │    └─ прочий SNI ─────────► nginx-local 9444 → cover-site               │
                        │                                                                        │
  браузер ────:80────────►  nginx 301 → https (cover + ACME)                                        │
                        └────────────────────────────────────────────────────────────────────────┘
```

### Три модуля (паттерн b4_monitor / b4_route_addon / dpi_bypass)

| Модуль | Роль | Что внутри |
|---|---|---|
| `chimera/modules/smartdns.py` | Оркестратор | Детект окружения, визард, preflight, транзакционная install/update/uninstall, status, backup/rollback, whitelist-меню, TUI-меню, CLI, state-файл |
| `chimera/modules/smartdns_stack.py` | Компонентный слой | Загрузки бинарников (download_manager), конфиги xray и движков, nginx (full/drop-in), cover-site генератор, Cloudflare sync, acme.sh, systemd-юниты, GeoHide-конвейер, dig-верификация, CLI для geo-таймеров |
| `chimera/modules/smartdns_firewall.py` | Firewall-слой | Чистые билдеры iptables/ip6tables/ufw, ipset-наборы, runtime-скрипты (firewall-apply, doh/dot-ватчеры), whitelist-операции |

Плюс инфраструктура Chimera: `port_registry` (IP-осознанные записи портов),
`download_manager` (PackageSpec + зеркала), `github_mirrors`
(build_mirror_urls), `box_renderer` (TUI).

### Порты стека

| Порт | Протокол | Кто слушает | Доступ | Тег port_registry |
|---|---|---|---|---|
| 80 | tcp | nginx (redirect 301 + ACME) | Публичный (companion: только bind_ip) | `smartdns_http` |
| 443 | tcp | **никто** — входящий 443 перехватывается NAT REDIRECT → 8444/9443 | — (не регистрируется) | — |
| 853 | tcp | xray dokodemo `dot-in` (DoT) | Публичный (companion: bind_ip) | `smartdns_dot` |
| 8444 | tcp | xray dokodemo `https-in` (stealth DoH/SNI-прокси) | Публичный (companion: bind_ip) | `smartdns_doh` |
| 9443 | tcp | nginx TLS (cover-site + `/resolve` + `/auth`) | Публичный (companion: bind_ip) | `smartdns_web` |
| 5353 | tcp+udp | DNS-движок (OxiDNS или AGH) — plain DNS | loopback | `smartdns_engine` |
| 8053 | tcp | DNS-движок DoH-эндпоинт (у AGH — и Web UI) | loopback | `smartdns_doh_local` |
| 8853 | tcp | nginx stream — DoT TLS-терминатор | loopback | `smartdns_dot_term` |
| 9444 | tcp | nginx stealth-фронт (proxy_protocol v1 от xray) | loopback | `smartdns_stealth` |

Важно понимать связку 443 → 9443/8444: **ни один процесс не слушает 443
напрямую**. Входящие соединения на 443 перехватываются в NAT-таблице
(PREROUTING) и перенаправляются: авторизованные (ipset) — на 8444 (xray,
SNI-прокси), все остальные — на 9443 (nginx, cover-site + DoH-эндпоинт).
Поэтому DoH-клиент, зашедший на `https://<домен>/resolve/<SECRET>`, на самом
деле попадает на nginx 9443 через NAT, а «изнутри» это выглядит как самый
обычный HTTPS-сайт.

В companion-режиме все публичные листенеры дополнительно привязаны ко второму
IP (bind_ip), а NAT-редиректы скоуплены `-d <bind_ip>` — подробности в
разделах 3, 13 и 15.

### systemd-юниты (полный неймспейс smartdns-*)

| Юнит | Тип | Назначение |
|---|---|---|
| `smartdns-xray.service` | persistent | Xray: dokodemo 8444/853, SNI-сниффинг, routing. `ExecStartPre` — `xray run -test -confdir` (конфиг невалиден → не стартует); жёсткий systemd-sandbox (ProtectSystem=strict, only CAP_NET_BIND_SERVICE) |
| `smartdns-oxidns.service` / `smartdns-adguardhome.service` | persistent | DNS-движок (один из двух, по выбору). У OxiDNS `ExecStartPre` — `oxidns check` (валидация YAML). Пользователи `oxidns` / `adguard` |
| `smartdns-firewall.service` | oneshot (RemainAfterExit) | Применяет ipset + iptables-цепочки из пререндеренного `/opt/smartdns/bin/smartdns-firewall-apply.py`; `ExecStop` — `ipset save` |
| `smartdns-doh-watcher.service` | persistent | Хвостит `/var/log/nginx/smartdns-auth.log`: успешные DoH-ответы и web-auth → `ipset add` (TTL 24 ч) |
| `smartdns-dot-watcher.service` | persistent | Хвостит `/var/log/smartdns/xray/access.log`: успешные DoT-хендшейки → `ipset add` |
| `smartdns-xray-reload.path` + `.service` | path + oneshot | Валидированный hot-reload: при изменении `rules.d/10-smartdns-routing.json` → `xray -test` → рестарт; провал → откат last-good |
| `smartdns-geosite-update.service` + `.timer` | oneshot + timer | Ежедневное обновление `geosite.dat` в 04:00 (Persistent=true, догоняет после даунтайма) |
| `smartdns-geohide-update.service` + `.timer` | oneshot + timer | Ежедневное обновление списка GeoHideDNS в 04:05 + перегенерация routing-правил |

Итого 12 юнитов — ни один не пересекается с юнитами стека Chimera
(`xray.service`, `adguardhome.service`, `nginx.service` и т. д.).

### Пользователи и группы

| Учётка | Тип | Роль |
|---|---|---|
| `smartdns` | system, nologin | Пользователь xray-инстанса стека (не путать с xray-пользователем Chimera) |
| `oxidns` | system, nologin | Пользователь движка OxiDNS |
| `adguard` | system, nologin | Пользователь движка AdGuardHome |
| `ssl-smartdns` | system group | Доступ к приватному ключу: в группе — `www-data` (nginx). Пользователь `smartdns` специально исключён из группы: xray-процесс стека TLS не терминирует и ключ не читает |

Движок и xray взаимно включены в группы друг друга (движок читает
`rules.d/`, xray — артефакты движка). Каталог данных `/var/lib/smartdns-dns-assets`
принадлежит пользователю движка с группой `smartdns` (режим 02750, setgid).

### Файлы и каталоги

| Путь | Права | Что лежит |
|---|---|---|
| `/opt/smartdns/bin/` | 755 root:root | `xray`, `oxidns`/`AdGuardHome` + runtime-скрипты `smartdns-firewall-apply.py`, `smartdns-{doh,dot}-watcher.py`, `smartdns-xray-safe-reload.py` |
| `/etc/smartdns/xray/conf.d/` | 750 root:smartdns | `00-base.json` (инбаунды/аутбаунды) + симлинк `10-smartdns-routing.json` → `rules.d/` |
| `/etc/smartdns/xray/rules.d/` | 750 smartdns:smartdns | `10-smartdns-routing.json` (routing-правила; источник для симлинка и path-юнита) |
| `/etc/smartdns/oxidns/config.yaml` | 640 | Конфиг OxiDNS |
| `/etc/smartdns/adguardhome/AdGuardHome.yaml` | 640 | Конфиг AdGuardHome |
| `/var/lib/xray-installer/smartdns/` | 700 root:root | `settings.json` (0640, без секретов), `secrets.json` (0600: CF-токен, ACME e-mail, креды панели AGH), `ipset-whitelist.save`, `backups/smartdns-<ts>.tar.gz` (0600) |
| `/var/lib/xray-installer/smartdns_state.json` | 600 | State оркестратора: installed/mode/engine/bind_ip/domain/dot_host/whitelist/versions/latest-кэш |
| `/var/lib/smartdns-dns-assets/` | 2750 | `geosite.dat`, `geohide-hosts.txt` (для OxiDNS), `geohide-domains.txt`, `ag-smartdns-rules.txt` (для AGH), `custom-allow.txt`, `custom-deny.txt` |
| `/etc/ssl/smartdns/` | 750 root:ssl-smartdns | `fullchain.pem` (644), `privkey.pem` (640) — wildcard-сертификат |
| `/var/www/smartdns-cover/` | 755 | Сгенерированный cover-site: `index.html`, `404.html`, `assets/style.css`, `favicon.svg` |
| `/var/log/smartdns/` | 755 | `xray/access.log`, `xray/error.log`, `certificate.log`, `firewall.log`, `xray.log` (safe-reload) |
| `/etc/nginx/conf.d/smartdns.conf` | — | http-drop-in (только в drop-in режиме; см. раздел 9) |
| `/etc/nginx/stream-conf.d/smartdns-dot.conf` | — | stream-drop-in DoT-терминатора |
| `/etc/sysctl.d/90-smartdns-keepalive.conf` | — | TCP keepalive + mtu_probing |

### Логи

| Файл | Кто пишет | Что там |
|---|---|---|
| `/var/log/chimera.log` | все три модуля | Единый лог Chimera, префикс `[smartdns]` |
| `/var/log/nginx/smartdns-access.log` | nginx | Общий доступ в формате `smartdns_doh_fmt` |
| `/var/log/nginx/smartdns-auth.log` | nginx | **Только верифицированные** DoH-ответы (`if=$smartdns_doh_verified`) и web-auth-хиты — этот файл читает DoH-ватчер |
| `/var/log/nginx/smartdns-dot.log` | nginx stream | DoT-сессии терминатора |
| `/var/log/smartdns/xray/access.log` | xray | Соединения с тегами in/out (`[dot-in -> dot-backend]` и т. п.) — читает DoT-ватчер |
| `/var/log/smartdns/firewall.log` | ватчеры | События авторизации IP |
| `/var/log/smartdns/certificate.log` | acme.sh | Полный вывод выпуска сертификата |

### ipset-наборы

| Набор | Семейство | Назначение |
|---|---|---|
| `smartdns_clients` / `smartdns_clients6` | inet / inet6 | Базовая авторизация: доступ к stealth-DoH/SNI-прокси (NAT 443→8444) |
| `dot_clients` / `dot_clients6` | inet / inet6 | Отдельный набор DoT (используется в режиме whitelist=separate) |

Все — `hash:ip` с `timeout 86400` (запись живёт 24 часа, потом удаляется
сама). Состояние периодически сохраняется в
`/var/lib/xray-installer/smartdns/ipset-whitelist.save` и восстанавливается
при старте `smartdns-firewall.service` — авторизации переживают ребут
(оставшееся время TTL сохраняется).

---

## 3. Режимы: standalone и companion (и почему «общий IP» отвергнут)

### Два режима — один инструмент

Решение владельца 17.11.2026: оба сценария развёртывания совмещены в одном
установщике, режим выбирается в визарде (или флагом `--mode`) на одной ноде
за один вопрос. Разница между режимами в коде — это ровно одна переменная
`bind_ip`, от которой зависят ~10 точек (листенеры xray/nginx, NAT-скоупы,
ufw-правила, записи port_registry, адрес CF-синхронизации, наличие
default_server у nginx, выбор движка).

| Аспект | standalone («Отдельный VPS») | companion («Этот VPS + второй IP») |
|---|---|---|
| Где живёт | Выделенный VPS только под SmartDNS | VPS с уже установленной Химерой + заказанный у хостера второй IP ($1–3/мес) |
| Публичные листенеры | wildcard (`0.0.0.0`) | строго `<bind_ip>` (второй IP) |
| NAT REDIRECT 443 | без ограничений по адресу | `-d <bind_ip>` — трафик на основной IP (VLESS Химеры!) не трогается |
| DROP/лимит-правила | wildcard | `-d <bind_ip>` (порты 9443/9444/8444/853 на основном IP — это User Portal/Subscription/AGH-DoT Химеры) |
| ufw | как bash: allow SSH/80/443/853 + `--force enable` | только per-IP: `ufw allow … to <bind_ip> port 80/853/8444/9443`; **никогда** `--force enable`, никогда 443 |
| nginx | пишем `/etc/nginx/nginx.conf` целиком (наш маркер в шапке), `default_server` на 80/9443 | только drop-in'ы: `conf.d/smartdns.conf` + `stream-conf.d/smartdns-dot.conf`; основной nginx.conf Химеры не трогаем (кроме stream-include-хука); без `default_server`; **reload** вместо restart |
| DNS-движок | OxiDNS или AdGuardHome (на выбор) | только OxiDNS (AGH Химеры занял бы и имя юнита, и порты; конфликт исключаем в принципе — preflight FAIL) |
| IPv6 | используется, если есть (AAAA обновляются при существовании записей) | не используется: AAAA-записи стека удаляются, листенеры — только IPv4 bind_ip |
| Cloudflare | A-записи → основной IP | A-записи → bind_ip (второй IP) |
| Требование к ОС | Debian 12/13, Ubuntu 22.04/24.04, x86_64 или arm64 | то же + второй IP уже поднят в ОС (проверяется preflight) |

### Почему третий режим («общий IP, мерж двух стеков») отвергнут в принципе

Технически можно было бы смержить стек Химеры и SmartDNS на одном IP: один
nginx, один xray, SNI-диспетчеризация двух стеков на 443. Этот вариант
исключён сознательно:

- **Максимум риска**: xray Химеры держит VLESS/REALITY на 443 — любой баг в
  merge-логике роняет VPN-сервис вместе с DNS-сервисом. Единая точка отказа
  из двух независимых продуктов.
- **Нулевая изоляция**: конфликтуют порт 443 (NAT-редиректы SmartDNS против
  REALITY-инбаунда), юниты, пути, GeoHide-роутинг (routing-правила двух
  стеков в одном конфиге xray), AGH (движок SmartDNS против AGH-стека
  Химеры).
- **Цена вопроса копеечная**: второй IP у большинства хостеров — $1–3/мес.
  Companion-режим даёт ту же экономию («один VPS») без единого из рисков
  выше: у стека Химеры свой IP, у SmartDNS — свой, изоляция на уровне ядра.

### Companion-разводка по IP: как это работает

Ядро Linux разрешает **одновременный** bind сокета на wildcard (`0.0.0.0:80`)
и на конкретный адрес (`203.0.113.7:80`) — specific-сокет забирает трафик
своего адреса, wildcard обслуживает остальные. На этом стоит вся companion-
архитектура:

- nginx Химеры слушает `0.0.0.0:80/9443/...` — как слушал;
- наш drop-in добавляет в **тот же процесс** nginx листенеры
  `<bind_ip>:80` и `<bind_ip>:9443 ssl` — они забирают соединения ко второму
  IP;
- xray стека (отдельный процесс `smartdns-xray`) слушает `<bind_ip>:8444` и
  `<bind_ip>:853` — Dokodemo на конкретном адресе;
- в iptables каждый REDIRECT/DROP снабжён `-d <bind_ip>`, поэтому цепочки
  смарт-DNS не видят трафик основного IP вовсе.

То же правило зашито в port_registry: записи стека несут поле `bind_ip`,
а конфликт-детект понимает, что wildcard-запись Химеры и specific-запись
SmartDNS на одном порту — **не конфликт** (функция `_bind_scopes_overlap`).
Preflight честно проверит занятость портов именно на bind_ip: слушатель
Химеры на `0.0.0.0:80` не помешает нашему листенеру на `<bind_ip>:80`.

### Что нужно для companion-режима до установки

1. **Заказать второй IP у хостера** (обычно через тикет/панель).
2. **Поднять его в ОС самому** — добавить адрес в netplan/interfaces так,
   как предписывает хостер. Инсталлятор принципиально не настраивает чужую
   сеть: preflight проверяет, что IP реально лежит на интерфейсе
   (`ip -4 addr show scope global`), и откажет, если нет.
3. Убедиться, что это **не** основной IP (равенство основному = FAIL
   preflight — основной остаётся Химере).
4. Желательно (не обязательно): выставить у хостера **PTR-запись** второго
   IP на DOT_HOST — для чистого DoT-хендшейка (некоторые клиенты проверяют
   обратную зону). Preflight напомнит.

### Авто-детект режима в визарде

Визард сам предлагает режим по умолчанию: если на ноде найдены маркеры
Химеры (`/var/lib/xray-installer/state.json`, `telegram.json`,
`/usr/local/bin/xray`, `/etc/xray/config.json`) **и** в ОС есть глобальные
IPv4 помимо основного — дефолтом подставляется companion (и список
кандидатов второго IP показывается готовым списком). Иначе дефолт —
standalone. Выбор всегда остаётся за пользователем.

---

## 4. Установка через меню (визард по шагам)

### Путь из главного меню

```
python3 main.py
→ Главное меню → 3 (Настройки сети)
→ Меню «Настройки сети» → SD (SmartDNS-нода)
→ Меню «SmartDNS — DoH/DoT Stealth + SNI Proxy»
```

Меню показывает состояние стека (установлен/не установлен, версия стека),
строку «Обновление: …→ [3]» при наличии свежих версий и пункты:

| Пункт | Действие |
|---|---|
| 1 | Установить (режимы: отдельный VPS / второй IP) — запуск визарда |
| 2 | Статус стека (подробный бокс, см. раздел 17) |
| 3 | Обновить компоненты |
| 4 | DoT/DoH whitelist (добавить/убрать/режим) |
| 5 | Бэкап / откат |
| 6 | Удалить стек |
| q / 0 / Enter | Назад |

Альтернативный запуск без главного меню:

```bash
python3 -m chimera.modules.smartdns menu
```

### Визард: экран за экраном

**Экран 1 — Режим.** Показывает, что обнаружено: «Химера — ДА/нет; вторые IP —
<список или нет>». Варианты: `1` — Отдельный VPS (standalone, полный стек,
порты wildcard); `2` — Этот VPS + второй IP (companion, изоляция по bind_ip,
nginx/фаервол Химеры не трогаем). Дефолт подставлен по авто-детекту.

**Экран 2 — Второй IP** (только companion). Если найдены кандидаты — выбор
номером из списка (дефолт — первый); иначе ручной ввод. IP обязан: быть
валидным IPv4, лежать на интерфейсе ОС, не совпадать с основным IP. Нарушение
— предупреждение и выход из визарда. На этом же экране: «Движок зафиксирован:
OxiDNS (AGH занят стеком Химеры)».

**Экран 2' — DNS-движок** (только standalone): `1` — OxiDNS (Rust,
geosite-блокировки, только x86_64); `2` — AdGuardHome (панель на
127.0.0.1:8053, все архитектуры). На не-x86_64 выбор OxiDNS автоматически
заменяется на AdGuardHome с предупреждением.

**Экран 3 — Домены и Cloudflare:**

- **Основной домен (ROOT_DOMAIN)** — например `example.com`. Используется
  для cover-site, DoH-URL (DoH живёт в **корне** домена), wildcard-записей
  и wildcard-сертификата. Валидация: FQDN, ≤253 символов.
- **Поддомен DoT (DOT_HOST)** — например `dns.example.com`. Дефолт:
  `<10 случайных символов>.<домен>`. Должен быть валидным поддоменом
  `*.<домен>` (не равным самому домену). На нём слушается DoT 853.
- **Секретный путь DoH/web-auth** — генерируется автоматически: 52 символа
  `[A-Za-z0-9]`. Результирует в два URL: `https://<домен>/resolve/<SECRET>`
  (DoH) и `https://<домен>/auth/<SECRET>` (закладка авторизации).
- **DoT IP-whitelist** — «Включить DoT IP-whitelist (853 только для
  авторизованных)?» Дефолт `n`. При `y` — выбор режима: `1` shared
  (общий с DoH) / `2` separate (отдельный набор для DoT). Подробнее —
  раздел 14.
- **GeoHide-опции** — «Добавить системные домены Google в GeoHide-список?»
  (дефолт `y`: apis.google.com, googleapis.com и пр. тоже резолвятся в адрес
  ноды и проксируются) и «Добавить домены Xbox/ipify?» (дефолт `n`:
  xboxlive.com, xbox.com, sfx.ms, msgamestudios.com).

**Экран 4 — Cloudflare:** API-токен с правами **Zone → DNS → Edit** на зону
домена (минимум 20 символов; подтягивается из secrets.json, если ставили
раньше) и ACME e-mail (дефолт `admin@<домен>`).

**Экран 5 — Сводка и подтверждение.** Режим (+bind_ip), движок, домен,
DoT-хост, whitelist-режим, порты («80, 853, 8444, 9443 + loopback»),
пояснение: на DoH-хост (он же cover-site) уйдут A/AAAA записи Cloudflare,
выпустится wildcard-сертификат (DNS-01). Подтверждение `y/N`.

### Что именно происходит при установке (19 шагов)

Установка транзакционна: перед началом создаётся бэкап, провал любого шага —
откат к состоянию до установки (распаковка бэкапа).

1. **Preflight** — полный набор проверок (раздел 6). FAIL = установка
   отменяется, ничего не меняется.
2. **Бэкап** — tar.gz текущего состояния конфигов стека (для отката).
3. **Системные пакеты** — `apt-get install`: curl, ca-certificates, gnupg2,
   lsb-release, jq, ufw, ipset, conntrack, dnsutils, openssl, tar, unzip,
   socat, cron, logrotate, python3-bcrypt. nginx: если уже установлен (в
   companion — это nginx Химеры) — **не трогаем вовсе**; если нет — ставим
   из официального репозитория nginx.org (ключ в keyring, pin-priority 900).
4. **Пользователи и каталоги** — см. таблицы раздела 2. Идемпотентно;
   существующие пользователи не пересоздаются.
5. **Бинарники** — xray + выбранный движок через download_manager: свежий
   GitHub release (авто-latest), при недоступном GitHub — проверенные
   фолбэк-теги (раздел 7). Возвращаются фактически установленные версии.
6. **settings.json + secrets.json** — настройки без секретов (0640) и
   секреты (0600: CF-токен, ACME e-mail; позже дописываются креды панели
   AGH).
7. **Cloudflare-синк** — A/AAAA записи домена/поддоменов на адрес стека
   (companion: на bind_ip) — детали в разделе 12.
8. **Wildcard-сертификат** — acme.sh, DNS-01 через dns_cf, ec-256; при
   наличии валидного — переиспользуется. Криптографическая верификация
   пары ключ/сертификат, SAN, срока.
9. **Xray base-конфиг** — `00-base.json` (инбаунды dokodemo 8444/853 c bind
   по режиму, аутбаунды, DNS) — раздел 8.
10. **geosite.dat** — свежий релиз Loyalsoldier/v2ray-rules-dat в
    `/var/lib/smartdns-dns-assets/`. Провал — не фатален: «таймер догонит
    ночью» (04:00).
11. **GeoHide-конвейер** — скачать hosts GeoHideDNS, распарсить с
    исключениями, сгенерировать артефакты движка + routing-правила,
    провалидировать `xray run -test` во временном confdir, атомарно
    применить, симлинк в conf.d, рестарт движка. Провал = фатален (без
    GeoHide-списка стек бессмыслен).
12. **Конфиг движка** — OxiDNS `config.yaml` или AGH `AdGuardHome.yaml`
    (для AGH генерируются логин `admin_<6 символов>` и пароль 24 символа —
    bcrypt-хэш в конфиг, пароль в secrets.json) — раздел 10.
13. **Cover-site** — процедурный генератор: случайный бренд («Nord Studio»,
    «Baltic Atelier»...), одна из 5 палитр, 4–7 «проектов», выравнивание
    hero, сетка 2–3 колонки, год. index.html + 404.html + style.css +
    favicon.svg в `/var/www/smartdns-cover`.
14. **nginx** — режим full (standalone на чистой машине: nginx.conf целиком,
    с бэкапом и `nginx -t`-гейтом) или drop-in (companion или чужой nginx:
    conf.d + stream-conf.d + идемпотентный stream-include-хук; основной
    конфиг не трогаем). Провал `nginx -t` — откат наших файлов и отмена
    установки. Применение — `systemctl reload` (не restart: у Химеры свои
    соединения). Раздел 9.
15. **Runtime-скрипты файрвола** — `smartdns-firewall-apply.py` (с
    пререндеренными правилами) + doh/dot-ватчеры.
16. **systemd-юниты** — все 12 юнитов, daemon-reload, старт в порядке:
    firewall → движок → xray → reload-path → ватчеры → таймеры; установка
    ждёт появления движка на `127.0.0.1:5353/udp` до 15 секунд (OxiDNS
    компилирует фильтры при первом старте).
17. **Файрвол** — sysctl keepalive, ipset-наборы (с восстановлением save),
    цепочки SMARTDNS_* (NAT + INPUT + OUTPUT, v4+v6), ufw-правила режима,
    **seed админского IP**: IP текущей SSH-сессии (из `$SSH_CLIENT`) тихо
    добавляется в whitelist на 24 часа. Раздел 13–14.
18. **port_registry** — регистрация 8 тегов (9 записей: 5353 — tcp и udp) с
    `force=True` (сервисы к этому моменту уже слушают) и `bind_ip` у
    публичных в companion.
19. **Верификация движка** — dig-пробы (раздел 17): апстрим+кэш, спуфинг
    GeoHide, AAAA NODATA. Провал — предупреждение (фильтры OxiDNS могут
    собираться дольше минуты), не откат.

Затем пишется state (`installed: true`, версии, режим...) и печатается
итоговый бокс:

```
┌─ SmartDNS — итоги установки ──────────────────────────────┐
│ DoH:       https://example.com/resolve/<52 символов>      │
│ Web-auth:  https://example.com/auth/<52 символов> (24ч)   │
│ DoT:       dns.example.com:853 (TLS)                      │
│ Версии:    xray v26.x.x, движок v1.7.x                    │
│ Bind IP:   203.0.113.7  (companion)                       │
│  Клиент: DNS приложения → DoH-URL выше (или Private DNS:  │
│  hostname DoT). Хром/Android-Private-DNS-пользователям    │
│  сначала открыть web-auth ссылку из нужной сети.          │
└───────────────────────────────────────────────────────────┘
```

### Где потом взять секретный путь DoH

Итоговый бокс показывается один раз, а в `settings.json` секретный путь
**не сохраняется** (специально — меньше копий секрета на диске). Источник
правды после установки — конфиг nginx:

```bash
grep -o 'location = /resolve/[A-Za-z0-9]*' /etc/nginx/conf.d/smartdns.conf \
  || grep -o 'location = /resolve/[A-Za-z0-9]*' /etc/nginx/nginx.conf
```

Второй URL (web-auth) отличается только `/auth/` вместо `/resolve/` — путь
у них общий.

---

## 5. Установка через CLI (флаги, non-interactive, exit-коды)

### Полная справка

```
Использование: python3 -m chimera.modules.smartdns <команда> [аргументы]

Команды:
  install [--mode standalone|companion] [--bind-ip IP] [--domain DOM]
          [--dot-host HOST] [--engine oxidns|adguardhome]
          [--cf-token TOKEN] [--acme-email EMAIL] [--non-interactive]
                                        Установка (без флагов — интерактивный визард)
  preflight [--mode ...] [--bind-ip IP]   Проверка готовности (read-only)
  status                                  Текущее состояние стека
  update                                  Обновить компоненты к последним release
  uninstall [--purge]                     Снять стек (с файлами при --purge)
  backup | rollback [PATH]                Бэкап конфигураций / откат
  whitelist add|remove IP | flush | toggle [on|off] | mode [shared|separate] | status
  menu                                    Интерактивное TUI-меню
```

Требование root: команды, меняющие систему (install/preflight/update/
uninstall/backup/rollback/whitelist), требуют root (`sudo`) — иначе
`[ERR] Требуется root (sudo)` и код 1. Без root работают только `status` и
`menu`.

### Интерактивная установка через CLI

```bash
# Без флагов — тот же визард, что и из меню:
sudo python3 -m chimera.modules.smartdns install

# Preflight в одиночку (ничего не меняет):
sudo python3 -m chimera.modules.smartdns preflight --mode companion --bind-ip 203.0.113.7
```

Флаги, переданные вместе с интерактивным визардом, работают как
предзаполнение (например, `--domain` подставится в соответствующий вопрос).

### Non-interactive установка (SSH-автоматизация, ansible и т. п.)

```bash
# standalone на чистом VPS:
sudo python3 -m chimera.modules.smartdns install \
    --mode standalone --domain example.com \
    --cf-token <CF_TOKEN> --non-interactive

# companion на ноде Химеры со вторым IP:
sudo python3 -m chimera.modules.smartdns install \
    --mode companion --bind-ip 203.0.113.7 --domain example.com \
    --cf-token <CF_TOKEN> --non-interactive
```

Контракты `--non-interactive` (все проверки — до единого изменения системы):

| Требование | Реакция на нарушение |
|---|---|
| `--domain` обязателен и валиден (FQDN) | `[ERR] --domain обязателен и должен быть валиден`, rc 1 |
| companion требует `--bind-ip` | `[ERR] companion требует --bind-ip`, rc 1 |
| `--cf-token` обязателен | `[ERR] --cf-token обязателен (--non-interactive)`, rc 1 |
| bind_ip поднят в ОС и не основной IP | `[ERR] <причина>`, rc 1 |
| `--engine adguardhome` + companion | движок молча форсируется в oxidns (AGH в companion запрещён) |

Что генерируется автоматически при non-interactive: `dot_host` =
`<10 случайных символов>.<домен>` (если не задан `--dot-host`), секретный
путь DoH — 52 случайных символа, whitelist — выключен/shared,
GeoHide-опции — Google-домены включены, Xbox выключены, ACME e-mail —
`admin@<домен>`, `server_ipv4` — bind_ip (companion) или основной IP
(standalone), `server_ipv6` — пусто в companion / основной v6 в standalone.

### Exit-коды

| Код | Значение |
|---|---|
| 0 | Успех (или справка `-h`/`--help`) |
| 1 | Ошибка выполнения: не root, preflight FAIL, установка не удалась (с откатом), uninstall/update при неустановленном стеке, невалидные аргументы whitelist |
| 2 | Неизвестная команда/подкоманда (после печати справки) |

### Прочие команды

```bash
python3 -m chimera.modules.smartdns status            # статус-бокс
sudo python3 -m chimera.modules.smartdns update       # обновление (раздел 16)
sudo python3 -m chimera.modules.smartdns uninstall --purge
sudo python3 -m chimera.modules.smartdns backup       # снимок конфигов
sudo python3 -m chimera.modules.smartdns rollback /var/lib/xray-installer/smartdns/backups/smartdns-20261117-120000.tar.gz

# whitelist (стек обязан быть установлен):
sudo python3 -m chimera.modules.smartdns whitelist add 198.51.100.23
sudo python3 -m chimera.modules.smartdns whitelist remove 198.51.100.23
sudo python3 -m chimera.modules.smartdns whitelist flush
sudo python3 -m chimera.modules.smartdns whitelist toggle on     # или off; без аргумента — инверт
sudo python3 -m chimera.modules.smartdns whitelist mode separate # или shared
sudo python3 -m chimera.modules.smartdns whitelist status        # JSON на stdout
```

Отдельный CLI есть у компонентного слоя (используется geo-таймерами, можно
запускать руками):

```bash
sudo python3 -m chimera.modules.smartdns_stack update-geosite   # только geosite.dat
sudo python3 -m chimera.modules.smartdns_stack update-geohide   # список GeoHide + routing
```

---

## 6. Preflight — проверки перед установкой

Запуск: `install` всегда проходит preflight первым шагом; отдельно —
`preflight` из CLI — по тем же флагам, что и install. Формат вывода — бокс
«SmartDNS — Preflight» со строками
`[ OK ]` / `[FAIL]` / `[WARN]` / `[INFO]` и итогом «СЕРВЕР ГОТОВ» либо
«ЕСТЬ БЛОКЕРЫ». FAIL любой строки = блокер установки.

### Общие проверки (оба режима)

| Проверка | Условие | Статус |
|---|---|---|
| ОС | Debian 12 (bookworm) / Debian 13 (trixie) / Ubuntu 22.04 (jammy) / Ubuntu 24.04 (noble) | иначе FAIL |
| RAM | ≥ 512 МБ | иначе FAIL |
| Диск (свободный на /) | ≥ 1500 МБ | иначе FAIL |
| Основной IPv4 | найден на интерфейсе default-маршрута | иначе FAIL |
| Химера на ноде | маркеры `/var/lib/xray-installer/state.json`, `telegram.json`, `/usr/local/bin/xray`, `/etc/xray/config.json` | INFO (не влияет) |
| Firewall backend | `iptables-nft` или `iptables-legacy` (по выводу `iptables --version`) | INFO |
| Порты | IP-осознанная проверка через port_registry: записи реестра + слушатели `ss` + ufw-правила; конфликт = FAIL | см. ниже |

### Проверки портов: IP-осознанность

Проверяются все порты плана (раздел 2). В companion-режиме loopback-порты
(5353/8053/8853/9444) по `ss` не проверяются — их слушатели появляются позже
и сидят на 127.0.0.1, где конфликтов не бывает; публичные порты проверяются
**с bind_ip**: wildcard-слушатель Химеры на `0.0.0.0:80` не конфликт, чужой
specific-адрес — не конфликт, слушатель на том же `bind_ip:80` — конфликт.
В standalone проверка классическая (любой слушатель порта = занят).

### Companion-блок проверок

| Проверка | Условие | Статус |
|---|---|---|
| Второй IP (bind) | валидный IPv4, поднят в ОС (`ip -4 addr show scope global`), ≠ основному | иначе FAIL с расшифровкой: «Закажите второй IP у хостера и поднимите его в netplan/interfaces — инсталлятор чужую сеть не настраивает» |
| Стек Химеры | маркеры найдены → «разводка по IP активна»; не найдены → WARN «режим всё равно допустим (второй IP будет зарезервирован за smartdns)» | OK / WARN |
| Движок | обязан быть oxidns («AGH конфликтует с AdGuard Home Химеры») | иначе FAIL |
| Архитектура | OxiDNS: официальные сборки только x86_64 | иначе FAIL |
| PTR второго IP | инсталлятор не проверяет | INFO: «выставьте PTR у хостера на DOT_HOST для чистого DoT-handshake» |

### Что preflight НЕ проверяет (осознанно)

- Доступность API Cloudflare и валидность токена — это выяснится на шаге
  CF-синка установки (там же внятная ошибка).
- Наличие PTR (см. выше) — рекомендация, не блокер.
- Существование DNS-зоны у вашего аккаунта Cloudflare — проверит CF-синк.

---

## 7. Компоненты, версии и зеркала загрузок

### Состав компонентов

| Компонент | Откуда | Фолбэк-тег (GitHub недоступен) | Ограничения |
|---|---|---|---|
| Xray-core | `XTLS/Xray-core` (releases) | `v26.11.9` | x86_64 (`Xray-linux-64.zip`) или arm64 (`Xray-linux-arm64-v8a.zip`) |
| OxiDNS | `svenshi/oxidns` (releases, asset `oxidns-x86_64-unknown-linux-musl.tar.gz`) | `v1.7.1` | **только x86_64** — официальные сборки |
| AdGuardHome | `AdguardTeam/AdGuardHome` (releases) | `v0.107.62` | x86_64 / arm64 / armv7 |
| geosite.dat | `Loyalsoldier/v2ray-rules-dat` (latest release) | — | минимальный размер 100 000 байт (защита от битой загрузки) |
| GeoHide-список | `Internet-Helper/GeoHideDNS`, ветка main, `hosts/hosts` (raw.githubusercontent) | — | минимум 5 доменов после парсинга, иначе откат |
| acme.sh | `acmesh-official/acme.sh`, master-tarball | — | ставится в `/root/.acme.sh` только если отсутствует |

### Механика резолва версий (паттерн B4)

- **Первоначальная установка**: для каждого компонента запрашивается
  последний **стабильный** релиз GitHub API (`/releases/latest`,
  pre-release игнорируются). Сеть недоступна / API молчит → берётся
  проверенный фолбэк-тег, зашитый в код. Установка **никогда не падает из-за
  недоступности метаданных версий**.
- **Сравнение версий** — `version_key`: кортеж чисел + признак release:
  `v26.11.9 > v26.11.9-rc1` (release старше pre-release при равных числах),
  мусорные строки считаются «не сравнимыми» `((0,), 0, '')`.
- **Кэш latest** (для строки «доступно новое» в шапке меню/статуса): при
  установленном стеке опрашивает GitHub не чаще раза в 6 часов (TTL 6 ч при
  успехе, 30 минут при неудаче — как `_refresh_b4_latest_cache`). Результаты
  лежат в `smartdns_state.json` (`latest_versions`, `latest_checked_at`,
  `latest_check_ok`).

### download_manager: как именно качаем

Все загрузки идут через `download_manager.fetch_package(PackageSpec)`:

- **Зеркала**: для release-артефактов применяются только GitHub и
  gh-прокси-семейство (jsDelivr / raw.githubusercontent / statically не
  раздают файлы релизов — они осознанно выключены в `build_mirror_urls`).
  При недоступности первого зеркала автоматически пробуется следующее.
- **Верификация xray**: пакет Xray скачивается вместе с `.dgst`-файлом
  (SHA512-суммы от XTLS) — checksum-гейт download_manager'а.
- **Минимальные размеры**: xray ≥ 5 МБ, AGH ≥ 5 МБ, OxiDNS ≥ 1 МБ, geosite
  ≥ 100 КБ — защита от HTML-заглушек вместо бинарников.
- **manual-incoming**: каталог `/root` — можно заранее положить архив
  вручную (например, `Xray.zip` / `smartdns-engine.tar.gz`), download_manager
  подхватит его при недоступности сети (классический офлайн-паттерн Chimera).
- **Куда ставится**: всё в `/opt/smartdns/bin/` — свои бинарники, никак не
  пересекающиеся с `/usr/local/bin/xray` Химеры.

### GeoHide-артефакты (что генерируется из списка)

После скачивания hosts-файла GeoHideDNS и парсинга (раздел 11) в
`/var/lib/smartdns-dns-assets/` пишутся три артефакта:

| Файл | Для кого | Формат |
|---|---|---|
| `geohide-hosts.txt` | OxiDNS (плагин `hosts` / `smart_a`) | построчно `domain:<домен> <SERVER_IP>` |
| `ag-smartdns-rules.txt` | AdGuardHome (фильтр `GeoHide SmartDNS Rules`) | `||<домен>^$dnstype=A,dnsrewrite=NOERROR;A;<SERVER_IP>` + `AAAA → NOERROR` + `HTTPS/SVCB → NOERROR` на каждый домен |
| `geohide-domains.txt` | OxiDNS (плагин `domain_set` / `proxied_sites`) | просто домены построчно |

---

## 8. Xray: прозрачный SNI-прокси (8444/853)

### Зачем здесь xray и что такое dokodemo-door

Свой бинарник xray (`/opt/smartdns/bin/xray`, юнит `smartdns-xray.service`,
пользователь `smartdns`) используется **не** как прокси-сервер, а как
прозрачный TCP-роутер: два инбаунда `dokodemo-door` принимают сырые TCP-потоки
и, полагаясь на **SNI-сниффинг** (разбор TLS ClientHello без терминирования
TLS), раскидывают их по правилам routing'а. Это позволяет: (а) снупить SNI у
DoT-клиентов до TLS-терминатора, (б) пускать «не наши» SNI на cover-site, а
«наши» и GeoHide — по адресатам, (в) не иметь в xray ни единого ключа.

### 00-base.json — инбаунды и аутбаунды

```json
{
  "log": {
    "access": "/var/log/smartdns/xray/access.log",
    "error": "/var/log/smartdns/xray/error.log",
    "loglevel": "info"
  },
  "dns": {
    "servers": ["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "tag": "https-in",
      "listen": "<bind>",            // companion: второй IP; standalone: 0.0.0.0
      "port": 8444,
      "protocol": "dokodemo-door",
      "settings": {"address": "127.0.0.1", "port": 443, "network": "tcp"},
      "sniffing": {"enabled": true, "destOverride": ["tls"], "routeOnly": false},
      "streamSettings": {"sockopt": {"tcpKeepAliveInterval": 120, "tcpNoDelay": true}}
    },
    {
      "tag": "dot-in",
      "listen": "<bind>",
      "port": 853,
      "protocol": "dokodemo-door",
      "settings": {"address": "127.0.0.1", "port": 8853, "network": "tcp"},
      "sniffing": {"enabled": true, "destOverride": ["tls"], "routeOnly": true},
      "streamSettings": {"sockopt": {"tcpKeepAliveInterval": 60, "tcpNoDelay": true}}
    }
  ],
  "outbounds": [
    {"tag": "direct-v4",    "protocol": "freedom",
     "settings": {"domainStrategy": "UseIPv4"},
     "streamSettings": {"sockopt": {"tcpKeepAliveInterval": 120}}},
    {"tag": "nginx-local",  "protocol": "freedom",
     "settings": {"redirect": "127.0.0.1:9444", "proxyProtocol": 1}},
    {"tag": "dot-backend",  "protocol": "freedom",
     "settings": {"redirect": "127.0.0.1:8853"}},
    {"tag": "block",        "protocol": "blackhole", "settings": {}}
  ]
}
```

Пояснения к ключевым полям:

- **`https-in` (8444)** — сюда NAT заворачивает входящий 443 (как
  авторизованный stealth-DoH/SNI-трафик, так и «остальных» — в зависимости от
  NAT-правила, см. раздел 13). `routeOnly: false` — сниффнутый SNI
  **подменяет адрес назначения**, поэтому routing решает по домену, а не по IP.
- **`dot-in` (853)** — DoT-клиенты. `routeOnly: true` — SNI используется
  только для маршрутизации, поток не модифицируется: TLS доходит до
  nginx-терминатора 8853 нетронутым.
- **`dns.servers`** (DoH к 1.1.1.1/8.8.8.8, IPv4-only) — резолвер самого
  xray: нужен для правил routing'а по доменам GeoHide (xray должен уметь
  превратить домен в IP для freedom/direct-v4).
- **Аутбаунды**: `direct-v4` — прямые исходящие (GeoHide-сайты); `nginx-local`
  — на stealth-фронт nginx 9444 **с proxy_protocol v1** (nginx восстановит
  реальный IP клиента из PROXY-заголовка — для лимитов и логов);
  `dot-backend` — на терминатор 8853; `block` — blackhole.
- **keepalive 120/60 с + tcpNoDelay** — анти-«полузакрытые» соединения,
  которыми любят душить DoT; в дополнение sysctl-файл стека (раздел 13).

### 10-smartdns-routing.json — правила по шагам

Файл лежит в `rules.d/` (владелец `smartdns`, чтобы его мог перегенерировать
geo-таймер) и **симлинкуется** в `conf.d/` — источник правды один. Правила
применяются сверху вниз, первое совпадение выигрывает:

```
1. inboundTag=dot-in,  domain=full:<DOT_HOST>          → dot-backend
2. inboundTag=dot-in,  port=0-65535                    → block
3. inboundTag=https-in, domain=[full:<домен>, full:www.<домен>,
                             full:<DOT_HOST>]          → nginx-local
4. inboundTag=https-in, domain=[domain:<g> для всех g из GeoHide] → direct-v4
5. inboundTag=https-in, ip=[<SERVER_IP>, 127/8, 10/8, 172.16/12,
                            192.168/16, 100.64/10, 169.254/16, ::1/128,
                            fc00::/7, fe80::/10 (+SERVER_IPv6)] → block
6. inboundTag=https-in, port=0-65535                   → nginx-local
```

Смысл каждого:

1. DoT-клиент с правильным SNI (DOT_HOST) → терминатор 8853 → движок.
2. Любой другой DoT (чужой SNI на 853 — сканеры, «попробовать 853 как
   HTTPS») → blackhole. Порт 853 отвечает только настоящему DoT на наш хост.
3. Прямое обращение браузера на сайт ноды (cover-site), DoH-эндпоинт
   (`/resolve/<SECRET>` живёт на том же домене) и web-auth → nginx.
4. **GeoHide-петля**: SNI совпал с заблокированным доменом из списка →
   freedom/direct-v4, xray сам соединяется с реальным сайтом от имени ноды.
   Клиент тем временем думает, что говорит с «сервером заблокированного
   сайта» — ведь DNS выдал ему SERVER_IP.
5. Анти-петля/анти-SSRF: если по каким-то правилам домен не снюффался, но
   назначением получился адрес самой ноды или приватные диапазоны — блок
   (иначе xray мог бы зациклиться сам на себя или уйти в локалку).
6. Всё остальное (любой другой SNI, без SNI) → cover-site. Скенер, подключившийся
   к 8444 с SNI `example.org`, увидит обычный сайт — как и случайный
   посетитель.

`domainStrategy: AsIs` в routing — домены не резолвятся заранее, решение
принимается по снюффанному имени (быстро, без лишних запросов).

### Валидация и hot-reload

- **Перед любым рестартом** конфиг проверяется: `xray run -test -confdir
  /etc/smartdns/xray/conf.d`. Юнит `smartdns-xray.service` делает то же в
  `ExecStartPre` — кривой конфиг физически не может уронить службу.
- **GeoHide-обновление** (таймер 04:05 или `update-geohide`) собирает новый
  routing.json **во временном confdir** (копия base + новый routing),
  прогоняет `xray -test` и только потом атомарно (`rename`) заменяет файл.
  Провал валидации → откат, старый список продолжает работать.
- **smartdns-xray-reload.path** следит за файлом `10-smartdns-routing.json`:
  изменение (например, руками) → запуск `smartdns-xray-safe-reload.py` →
  `xray -test`; успех → копия в `lastgood` + рестарт юнита; провал →
  восстановление lastgood и отказ (стек продолжает работать на старых
  правилах). Отказ пишется в `/var/log/smartdns/xray.log`.

---

## 9. nginx: cover-site, DoH-эндпоинт, web-auth и DoT-терминатор

### Два режима конфигурации nginx

Режим выбирается автоматически в `apply_nginx()`:

- **full** — standalone на машине, где nginx.conf либо отсутствует, либо
  уже написан нами (маркер `# managed by smartdns-installer (chimera)` в
  шапке). Пишем `/etc/nginx/nginx.conf` **целиком** (user www-data, worker
  auto, events 2048/multi_accept, stream-блок, http-блок с нашими
  директивами и серверами), листенеры `80 default_server` +
  `[::]:80 default_server` и `9443 ssl default_server` — wildcard. Перед
  записью — бэкап `nginx.conf.smartdns-bak-<ts>`.
- **drop-in** — companion (nginx принадлежит Химере) **или** standalone, где
  nginx.conf уже существует и не наш. Пишем только:
  - `/etc/nginx/conf.d/smartdns.conf` — http-директивы + server-блоки;
  - `/etc/nginx/stream-conf.d/smartdns-dot.conf` — stream-сервер DoT;
  - **stream-include-хук** (см. ниже), если основной конфиг ещё не знает про
    `stream-conf.d`.

  Публичные листенеры — строго `<bind_ip>:80` и `<bind_ip>:9443 ssl`,
  **без** `default_server` (соседство с серверами Химеры в одном процессе).
  Основной `/etc/nginx/nginx.conf` не переписывается.

Оба режима завершаются гейтом `nginx -t`: провал → восстановление наших
бэкапов (или удаление наших файлов, если бэкапов нет) → установка
отменяется. Успех → `systemctl reload nginx` — **reload, не restart**:
соединения Химеры и клиентов не рвутся.

### stream-include-хук (идемпотентный)

Стандартный `/etc/nginx/nginx.conf` из пакетов знает про `conf.d` (http), но
не про stream-подключения. Хук `ensure_stream_include`:

- если `stream-conf.d` уже упомянут в конфиге — ничего не делает;
- если есть блок `stream { ... }` — вставляет первой строкой блока
  `include /etc/nginx/stream-conf.d/*.conf;`;
- если `stream {}` нет — дописывает в конец файла:

```nginx
# managed by smartdns-installer (chimera)
stream {
    include /etc/nginx/stream-conf.d/*.conf;
}
```

Правится **только** stream-часть; http/user/events не трогаются. Это тот же
паттерн, что у singbox-модуля Химеры (`singbox_nginx`). Повторная установка —
no-op.

### http-директивы (неймспейс smartdns_*)

Все директивы уровня http (в drop-in режиме — верхняя часть
`conf.d/smartdns.conf`) имеют префикс `smartdns_`, чтобы гарантированно не
столкнуться с http-контекстом nginx Химеры:

- **limit_req_zone**: `smartdns_doh` — 200 r/s (DoH-эндпоинт), `smartdns_web`
  — 30 r/s (cover-site и web-auth).
- **map $smartdns_doh_get_ok** — GET-запрос на `/resolve/...` валиден только
  с параметром `?dns=<base64url 12–2048 символа>` (RFC 8484);
- **map $smartdns_doh_post_ok** — POST валиден только с
  `Content-Type: application/dns-message`;
- **map $smartdns_doh_req_valid** — объединение: не-DoH-запросы к секретному
  пути получают 404, как обычный сайт без такой страницы;
- **map $smartdns_web_auth_ok** — web-auth принимает только GET/HEAD;
- **map $smartdns_doh_verified** — успешным DoH-ответом считается только
  `status 200 + upstream 200 + application/dns-message` (по этому флагу
  пишется лог для ватчера).

Лог-форматы: `smartdns_doh_fmt` (`время|IP|статус|upstream|тип|байты`) и
`smartdns_web_fmt` (то же, но `web-auth-verified` вместо типа).

### Server :80 — «обычный сайт начинается с редиректа»

```nginx
server {
    listen 80 default_server;        # drop-in: <bind_ip>:80
    server_name _;
    location ~ ^/(generate_204|gen_204)$ { return 204; }   # captive-чек как у больших
    location / { return 301 https://$host$request_uri; }
}
```

`/generate_204` отвечает 204 без редиректа — стандартная точка проверки
соединения (как у Google), чтобы redirect-поведение сайта не выделялось на
фоне живых интернетов. ACME-челленджи HTTP-01 сюда не завязаны (сертификат
выпускается по DNS-01), поэтому чистый 301 безопасен.

### Unified Stealth Server: 9443 + 127.0.0.1:9444 (proxy_protocol)

Один server-блок обслуживает и «публичный» 9443 (браузеры, DoH-клиенты,
сканеры), и внутренний 9444 (поток от xray `https-in` с proxy_protocol):

```nginx
server {
    listen 9443 ssl default_server;              # drop-in: <bind_ip>:9443 ssl
    listen 127.0.0.1:9444 ssl proxy_protocol;
    http2 on;
    server_name <домен> www.<домен> <DOT_HOST> _;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;               # реальный IP клиента из PROXY v1

    ssl_certificate     /etc/ssl/smartdns/fullchain.pem;
    ssl_certificate_key /etc/ssl/smartdns/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Robots-Tag "noindex, nofollow" always;

    root /var/www/smartdns-cover;
    error_page 404 /404.html;
    ...
}
```

Заголовки — консистентный TLS-фингерпринт узла (HSTS 2 года — как на фронтах
панелей Chimera; см. РКН-аудит 16.11 в docs/changelog/2026-11.md). Внутри —
три location:

**`location = /auth/<SECRET>`** — закладка авторизации:

```nginx
location = /auth/<SECRET> {
    limit_req zone=smartdns_web burst=15 nodelay;
    if ($smartdns_web_auth_ok = 0) { return 404; }     # только GET/HEAD
    default_type text/html;
    add_header Cache-Control "no-store, ..." always;
    access_log /var/log/nginx/smartdns-auth.log smartdns_web_fmt;
    return 200 '<!DOCTYPE html>… Session Synchronized … <strong>$remote_addr</strong>
                is verified … (24h lease) …';
}
```

Открыл ссылку в браузере из нужной сети → IP зафиксирован в логе → DoH-ватчер
добавит его в ipset на 24 часа (и в DoT-набор — режим separate/общий).

**`location = /resolve/<SECRET>`** — DoH-эндпоинт:

```nginx
location = /resolve/<SECRET> {
    limit_req zone=smartdns_doh burst=300 nodelay;
    if ($smartdns_doh_req_valid = 0) { return 404; }   # не-DoH → как обычный 404
    proxy_http_version 1.1;
    proxy_request_buffering on;
    proxy_buffering on;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_hide_header Server;
    proxy_hide_header X-Powered-By;
    proxy_pass http://127.0.0.1:8053/dns-query;        # DoH движка
    access_log /var/log/nginx/smartdns-auth.log smartdns_doh_fmt if=$smartdns_doh_verified;
}
```

Каждый неуспешный/мусорный запрос выглядит как 404 обычного сайта. В лог
(и далее в ватчер) попадают только **верифицированные** DoH-обмены.

**`location /`** — сам cover-site: `limit_req zone=smartdns_web burst=40
nodelay; try_files $uri $uri/ =404;` — статика визитки + честный 404 на
несуществующие пути (404.html из генератора).

### stream: DoT-терминатор 8853

```nginx
# /etc/nginx/stream-conf.d/smartdns-dot.conf
server {
    listen 127.0.0.1:8853 ssl;
    ssl_certificate     /etc/ssl/smartdns/fullchain.pem;
    ssl_certificate_key /etc/ssl/smartdns/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_handshake_timeout 10s;
    proxy_pass 127.0.0.1:5353;      # plain-DNS движка
    proxy_timeout 30s;
    proxy_connect_timeout 5s;
    access_log /var/log/nginx/smartdns-dot.log '…|время|IP|протокол|статус|байты…';
}
```

Почему терминатор — nginx, а не движок: у AGH TLS в стеке выключен по
построению (терминацией занимается nginx), у OxiDNS TLS-сервера нет вовсе;
так оба движка живут в одинаковых условиях, а сертификат применяется в одном
месте. SNI при этом уже проверен xray-правилом `full:<DOT_HOST>` — до
терминатора чужие не доходят (blackhole).

---

## 10. DNS-движки: OxiDNS и AdGuardHome

### Сравнение

| | OxiDNS | AdGuardHome |
|---|---|---|
| Язык | Rust | Go |
| Архитектуры | только x86_64 (официальные сборки) | x86_64 / arm64 / armv7 |
| Конфиг | `/etc/smartdns/oxidns/config.yaml` | `/etc/smartdns/adguardhome/AdGuardHome.yaml` |
| Фильтрация рекламы | geosite `category-ads-all` → NXDOMAIN (reject 3) | фильтр AdGuard SDNS |
| Web-панель | нет | да — 127.0.0.1:8053 (совмещён с DoH-портом) |
| Кэш | 4096 записей, кэш негативных | 4 МБ |
| Upstream | DoH 1.1.1.1 + 8.8.8.8 | DoH 1.1.1.1 + 8.8.8.8, bootstrap 1.1.1.1/8.8.8.8 |
| Companion-режим | **обязателен** (AGH Химеры занял бы имя/порты) | запрещён |
| Юнит | `smartdns-oxidns.service` (ExecStartPre: `oxidns check`) | `smartdns-adguardhome.service` (`--no-check-update`) |
| Рабочий каталог | `/var/lib/smartdns-oxidns` | `/var/lib/smartdns-adguardhome` |

### Конфиг OxiDNS (полностью)

```yaml
log:
  level: info

plugins:
  - tag: ads_domains
    type: geosite
    args:
      file: "/var/lib/smartdns-dns-assets/geosite.dat"
      selectors:
        - "category-ads-all"

  - tag: proxied_sites
    type: domain_set
    args:
      files:
        - "/var/lib/smartdns-dns-assets/geohide-domains.txt"

  - tag: smart_a
    type: hosts
    args:
      files:
        - "/var/lib/smartdns-dns-assets/geohide-hosts.txt"

  - tag: cache
    type: cache
    args:
      size: 4096
      short_circuit: true
      cache_negative: true

  - tag: upstream_doh
    type: forward
    args:
      upstreams:
        - addr: "https://1.1.1.1/dns-query"
        - addr: "https://8.8.8.8/dns-query"

  - tag: main
    type: sequence
    args:
      - matches: "qname $ads_domains"
        exec: "reject 3"                    # NXDOMAIN — реклама
      - matches:
          - "qname $proxied_sites"
          - "qtype 64 65"
        exec: "reject 5"                    # REFUSED — HTTPS/SVCB у GeoHide
      - matches:
          - "qname $proxied_sites"
          - "qtype 1 28"
        exec: "$smart_a"                    # A/AAAA → hosts (спуф)
      - matches: "has_resp"
        exec: "accept"
      - exec: "$cache"
      - matches: "!has_resp"
        exec: "$upstream_doh"

  - tag: udp_local
    type: udp_server
    args: { entry: "main", listen: "127.0.0.1:5353" }

  - tag: tcp_local
    type: tcp_server
    args: { entry: "main", listen: "127.0.0.1:5353" }

  - tag: doh_local
    type: http_server
    args:
      listen: "127.0.0.1:8053"
      entries:
        - path: "/dns-query"
          exec: "main"
```

Ключевая семантика sequence (порядок важен):

1. Домен из `category-ads-all` → сразу NXDOMAIN (реклама режется до всего
   остального, GeoHide тут ни при чём).
2. GeoHide-домен с qtype **HTTPS(64)/SVCB(65)** → REFUSED: запись типа
   HTTPS несёт IP-адреса и ECH-параметры, которые обошли бы спуф A-записей.
3. GeoHide-домен с qtype **A(1)/AAAA(28)** → `smart_a`: hosts-файл отвечает
   A = SERVER_IP; для AAAA — пустой NOERROR (NODATA): v6-адреса у стека нет,
   клиент обязан вернуться на IPv4.
4. Есть ответ (кэш/hosts) → отдать; иначе → кэш → апстрим DoH.

### Конфиг AdGuardHome (существенные части)

```yaml
http:
  address: 127.0.0.1:8053          # Web UI И DoH-эндпоинт (allow_unencrypted_doh)
  session_ttl: 720h
users:
  - name: "admin_<6 символов>"     # сгенерирован; пароль — bcrypt-хэш
    password: "$2b$…"
dns:
  bind_hosts: [127.0.0.1]
  port: 5353
  upstream_dns: [https://1.1.1.1/dns-query, https://8.8.8.8/dns-query]
  bootstrap_dns: [1.1.1.1, 8.8.8.8]
  cache_size: 4194304
  ratelimit: 0                     # лимиты держит nginx/xray/iptables
  refuse_any: true
  serve_plain_dns: true
tls:
  enabled: false                   # TLS терминирует nginx/xray стека
  port_https: 0
  port_dns_over_tls: 0
  allow_unencrypted_doh: true      # безопасно: слушает только loopback
filters:
  - url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
  - url: /var/lib/smartdns-dns-assets/ag-smartdns-rules.txt   # GeoHide-спуф
    name: GeoHide SmartDNS Rules
    id: 2
```

Пара «логин + пароль панели» генерируется при установке: логин
`admin_<6 случайных символов>`, пароль — 24 случайных символа. Пароль
попадает в `/var/lib/xray-installer/smartdns/secrets.json` (0600) в
открытом виде, в конфиг AGH — только bcrypt-хэш (python3-bcrypt, фолбэк —
`htpasswd -nbB`).

### Как попасть в панель AGH (standalone + движок AGH)

Панель слушает только 127.0.0.1:8053 — наружу не торчит:

```bash
ssh -L 8053:127.0.0.1:8053 root@<сервер>
# браузер: http://localhost:8053 — логин/пароль из secrets.json:
sudo cat /var/lib/xray-installer/smartdns/secrets.json
```

В панели работают фильтры и статистика запросов. Не рекомендуется менять
`dns.port`/`bind_hosts`/секцию `tls` — стек рассчитан на текущую схему
портов (порт меняет смысл: 5353 — plain, 8053 — DoH/панель).

---

## 11. GeoHide: спуфинг заблокированных доменов — полная петля

### Откуда берётся список

**GeoHideDNS** (`Internet-Helper/GeoHideDNS`) — публичный hosts-файл с
доменами, заблокированными в РФ. Стек скачивает сырую версию
(`refs/heads/main/hosts/hosts`) и прогоняет через парсер — полный паритет
awk-конвейера bash-установщика:

- из каждой строки hosts вытаскиваются домены (строки без IP — тоже
  доменные списки), `*.foo` нормализуется в `foo`, валидация FQDN;
- **безусловные исключения** (нельзя перехватывать, пока устройство не
  авторизовано — иначе каптив-чек Wi-Fi зависает): `x.com`/`*.x.com`,
  `meta.ai`/`*.meta.ai`, `connectivitycheck.gstatic.com`,
  `connectivitycheck.android.com`, `clients*.google.com`,
  `captive.apple.com`, `connect.rom.miui.com`, `msftconnecttest.com`,
  `msftncsi.com` (+поддомены);
- **опционально Google-системные** (вопрос визарда, дефолт — включены в
  список): `apis.google.com`, `suggestqueries.google.com`,
  `clients6.google.com`, `clients.google.com`, `withgoogle.com`,
  `o.pki.goog`, `googleapis.com`, `generativelanguage.googleapis.com`;
- **опционально Xbox** (дефолт выключены): `xboxlive.com`, `xbox.com`,
  `sfx.ms`, `msgamestudios.com`;
- `generativelanguage.googleapis.com` — **всегда** в списке (ключевой кейс
  разблокировки ИИ-сервисов);
- **свои списки**: `/var/lib/smartdns-dns-assets/custom-allow.txt` (домены
  добавить) и `custom-deny.txt` (исключить) — по одному домену в строке,
  читаются при каждом обновлении;
- защита от битого списка: меньше 5 доменов после парсинга → отказ,
  старый список продолжает работать.

### Петля по шагам (что происходит, когда клиент открывает заблокированный сайт)

```
1. Устройство использует ноду как DNS (DoH или DoT).
2. Движок получает A-запрос <заблокированный домен>:
     домен в GeoHide-списке → smart_a/hosts → ответ: A = SERVER_IP
     (AAAA → NODATA, HTTPS/SVCB → REFUSED — обходы отрезаны)
3. Браузер соединяется с 443/TCP SERVER_IP (думает, что это и есть сайт).
4. Ядро: NAT PREROUTING —
     источник в ipset smartdns_clients → REDIRECT на 8444 (xray)
     прочие                        → REDIRECT на 9443 (nginx cover)
5. xray https-in сниффает SNI из ClientHello:
     SNI = домен из GeoHide-списка → routing-правило 4 → freedom direct-v4
       → xray сам открывает TCP к реальному <домен>:443 от имени ноды
       → ход данных: клиент ↔ xray ↔ реальный сайт (TLS сквозной, end-to-end)
     SNI = наш домен / DOT_HOST   → nginx-local 9444 (cover/DoH/web-auth)
     прочий SNI / без SNI         → nginx-local 9444 (cover-site)
6. Неавторизованный клиент при этом получает просто cover-site —
   как любой случайный посетитель.
```

Итог: на устройстве **не установлен никакой прокси-клиент** — оно
использует вашу ноду как DNS-сервер (одна строка в настройках ОС/роутера),
а заблокированные сайты открываются. Весь обход — на стороне сервера.

### Обновление списка

- Ежедневно в **04:05** таймер `smartdns-geohide-update.timer`
  (Persistent=true — догонит после даунтайма): скачать → распарсить →
  перегенерировать артефакты движка → собрать routing.json → `xray -test`
  во временном confdir → атомарная замена → рестарт движка. Провал любой
  ступени — откат, стек работает на прежнем списке.
- geosite.dat обновляется отдельным таймером в **04:00** (для
  category-ads-all у OxiDNS).
- Вручную: `sudo python3 -m chimera.modules.smartdns_stack update-geohide`
  (и `update-geosite`).
- При смене адреса ноды (SERVER_IP) список надо перегенерировать — hosts
  вшивает адрес: запустите `update` (раздел 16) или руками
  `update-geohide` после правки `server_ipv4` в settings.json.

---

## 12. Cloudflare и wildcard-сертификат

### Что именно делает CF-синк

Токен (права **Zone → DNS → Edit**, зона домена должна быть активна в этом
аккаунте Cloudflare) — единственный секрет, который вводится при установке.
Синхронизация (`sync_cloudflare_records`) находит zone_id по имени домена и
приводит записи к адресату стека — в companion это **bind_ip** (второй IP),
в standalone — основной IPv4 ноды:

| Запись | Что делает | Почему так |
|---|---|---|
| `A <домен>` | upsert: обновляет существующую или **создаёт** | DoH/cover-site живут в корне домена |
| `A *.<домен>` | upsert: обновляет или **создаёт** | wildcard покрывает DOT_HOST (см. следующую строку) |
| `A <DOT_HOST>` | только **обновляет** существующую | отдельной записи не нужно — резолвится через wildcard; но если владелец создал свою — она обязана указывать на ноду |
| `AAAA <домен> / *.<домен> / <DOT_HOST>` | только при наличии v6 у стека (standalone): обновляют существующие; **если v6 нет (всегда в companion) — удаляются** | стек не слушает v6; оставшаяся AAAA уводила бы клиентов в пустоту |
| TTL / proxy | `ttl=120`, `proxied=false` (DNS only) | proxied-запись сломала бы и DoT 853, и NAT-геометрию |

**Важно про выбор домена:** инсталлятор переписывает A-записи **корня**
домена и wildcard. Не указывайте домен, который обслуживает что-то ещё
(например, основной домен панели Химеры на том же VPS) — берите отдельный
домен или выделенную DNS-зону под SmartDNS.

### Сертификат: wildcard через DNS-01

Сертификат — Let's Encrypt wildcard `<домен>` + `*.<домен>`, выпускается
acme.sh через challenge **DNS-01** (`--dns dns_cf`, ключ `CF_Token` из
окружения), ключ EC-256. Почему DNS-01, а не HTTP-01: wildcard иначе не
выпустить, а DoT-хост (DOT_HOST) обязан попадать под тот же сертификат без
отдельного выпуска.

Последовательность `issue_wildcard_certificate`:

1. Если пара в `/etc/ssl/smartdns/` уже валидна — **переиспользуется**,
   ничего не выпускается. «Валидна» = `verify_tls_keys`:
   - SHA-256 публичного ключа сертификата == SHA-256 публичного ключа
     privkey.pem (криптографическая пара, а не просто «файл есть»);
   - SAN содержит ровно **2** записи: `DNS:<домен>` и `DNS:*.<домен>`;
   - до истечения > 24 часов (`openssl -checkend 86400`).
2. acme.sh отсутствует → ставится в `/root/.acme.sh` из master-tarball'а
   GitHub с `--nocron` (собственный cron acme.sh не ставится — продлением
   управляет `update` стека, см. раздел 16).
3. Выпуск `--issue --dns dns_cf -d <домен> -d *.<домен> --keylength ec-256`;
   полный лог — в `/var/log/smartdns/certificate.log`.
4. `--install-cert` во временную директорию → повторная `verify_tls_keys`
   уже на свежей паре (не верим на слово) → атомарное копирование в
   `/etc/ssl/smartdns/` (fullchain 644, privkey 640 root:ssl-smartdns).

Приватный ключ читают только root и группа `ssl-smartdns` (nginx/www-data).
Xray-процесс стека ключа не касается вовсе — TLS у него не терминируется.

### Если выпуск упал

- «проверьте CF_API_TOKEN/зону» — токен без прав DNS:Edit на ЭТУ зону, зона
  не активна, либо api.cloudflare.com недоступен с ноды;
- лог с полным ответом ACME — `/var/log/smartdns/certificate.log`;
- после правки токена повторите установку (или `update`) — валидного
  сертификата ещё нет, будет попытка выпуска.

---

## 13. Файрвол: iptables, ufw и companion-разводка

Слой `smartdns_firewall.py`. Все правила собираются **чистыми билдерами**
(функции без side-эффектов — они же покрыты тестами), применяются
идемпотентно (цепочки пересоздаются, jump'ы вешаются при отсутствии).

### sysctl

`/etc/sysctl.d/90-smartdns-keepalive.conf` + `sysctl --system`:

```
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 4
net.ipv4.tcp_mtu_probing = 1
```

Keepalive в тонусе «полузакрытые» соединения (любимый способ душить DoT),
mtu_probing страхует PMTUD через туннели клиентов.

### Цепочки

| Цепочка | Таблица | Куда вешается |
|---|---|---|
| `SMARTDNS_PREROUTING` / `SMARTDNS6_PREROUTING` | nat | PREROUTING |
| `SMARTDNS_INPUT` / `SMARTDNS6_INPUT` | filter | INPUT |
| `SMARTDNS_OUTPUT` / `SMARTDNS6_OUTPUT` | filter | OUTPUT |

### NAT: входящий 443 (v4)

```
SMARTDNS_PREROUTING:
  1. -s 127.0.0.0/8 | 10/8 | 172.16/12 | 192.168/16 | 100.64/10 |
     169.254/16 | <SERVER_IP>/32            → RETURN      (не трогаем локальные и себя)
  2. [-d <BIND_IP>] -p tcp --dport 443 -m set --match-set smartdns_clients src
                                          → REDIRECT --to-ports 8444
  2a. (только whitelist_mode=separate)
      [-d <BIND_IP>] -p tcp --dport 443 -m set --match-set dot_clients src
                                          → REDIRECT --to-ports 8444
  3. [-d <BIND_IP>] -p tcp --dport 443   → REDIRECT --to-ports 9443
```

`[-d <BIND_IP>]` — скоуп companion-режима: без него REDIRECT перехватил бы
и 443 основного IP, где живёт VLESS/REALITY Химеры. Раньше whitelist-правил
— RETURN (приватные источники никогда не редиректятся), после — catch-all на
cover-site: неавторизованный посетитель видит сайт, а не таймаут.

v6-цепочка `SMARTDNS6_PREROUTING` зеркальна (RETURN для ::1/fe80/fc00 и
своего v6; те же два REDIRECT) — **без** адресного скоупа: в companion у
стека нет v6-адреса вовсе (AAAA удалены, листенеры — только v4 bind_ip),
поэтому до этих правил v6-трафик стека не доходит; в standalone они
обслуживают ноду при наличии v6.

### INPUT: защита служебных портов (v4)

```
SMARTDNS_INPUT:
  1. -p tcp ! --syn -m conntrack --ctstate INVALID → REJECT tcp-reset
  2. -m conntrack --ctstate ESTABLISHED,RELATED   → ACCEPT
  3. 853/TCP:
       whitelist ВКЛ:  [-d BIND] -m set --match-set <dot_clients|smartdns_clients>
                        src -m hashlimit --hashlimit-upto 30/min --hashlimit-burst 40
                        → ACCEPT; затем 853 → DROP
       whitelist ВЫКЛ: 853 --syn -m hashlimit --hashlimit-above 30/min
                        --hashlimit-burst 40 → DROP; затем 853 → ACCEPT
  4. -i lo → ACCEPT
  5. 9443: только DNAT-трафик (--ctstate DNAT --ctorigdstport 443) → ACCEPT;
     прямой стук в 9443 → DROP
  6. tcp multiport 8443,9444,8853,5353,8053,3000 [-d BIND] → DROP
  7. udp 5353 [-d BIND] → DROP
  8. 8444: DNAT(ctorigdstport 443) + smartdns_clients → ACCEPT
     (+ dot_clients при separate); иначе 8444 → DROP
```

Смысл: извне достижимы только 80 (сам nginx), 853 (DoT, с лимитом) и
«виртуальный» 443 (NAT). Прямые пробы 9443/8444/внутренних портов
глушатся — принять их можно только пройдя через NAT-редирект, т. е. как
легитимный 443-клиент. Правило 6 заодно закрывает соседние служебные порты
(3000 — дефолт AGH-инсталляций, 8443 — типовой HTTPS-альтернатив), чтобы
ничего не протекало. В companion правила 3, 5–8 скоуплены `-d <BIND_IP>` —
9443/9444/853 на **основном** IP принадлежат User Portal, Subscription и
AGH-DoT Химеры и продолжают работать как раньше.

### OUTPUT: анти-петля для пользователя smartdns (v4)

```
SMARTDNS_OUTPUT (uid = smartdns):
  1. ESTABLISHED,RELATED → ACCEPT
  2. uid smartdns → 127.0.0.1 tcp multiport 9443,9444,8853 → ACCEPT
     (единственные легитимные внутренние цели: nginx-фронты)
  3. uid smartdns → <SERVER_IP>/32, 127/8, 10/8, 172.16/12, 192.168/16,
     100.64/10, 169.254/16 → REJECT tcp-reset, затем DROP
     (xray не может соединиться «сам на себя» или в локалку — SSRF/петли)
```

В companion скоуп по адресу не нужен: UID `smartdns` уникален, других
процессов под ним нет. v6-зеркало — то же для ::1/fe80/fc00 (+свой v6).

### ufw

| Режим | Команды |
|---|---|
| standalone | `ufw allow <ssh-порт>/tcp` (порт детектится по слушающему sshd), `allow 80/tcp`, `allow 443/tcp` («SmartDNS HTTPS / SNI Proxy»), `allow 853/tcp`, затем `ufw --force enable` |
| companion | только четыре per-IP правила: `ufw allow proto tcp from any to <BIND_IP> port {80, 853, 8444, 9443} comment smartdns-…`. **Никогда** `--force enable`, никогда дефолт-политики, никогда 443 |

Почему в companion нет 443: на основном IP 443 принадлежит Химере (и уже
открыт её файрволом); на втором IP входящий 443 после NAT приходит уже на
порты 8444/9443 — которые мы и открываем. Открытие «443 на любой адрес»
меняло бы политику для чужого IP.

### Runtime: smartdns-firewall-apply.py

`smartdns-firewall.service` (oneshot, RemainAfterExit) запускает
`/opt/smartdns/bin/smartdns-firewall-apply.py` — **self-contained** скрипт
с зашитым JSON'ом правил (снапшот билдеров на момент генерации: режим,
bind_ip, whitelist-режим уже «впечатаны»). Скрипт создаёт ipset'ы,
восстанавливает `ipset-whitelist.save`, накатывает правила и сохраняет
ipset. При изменении настроек (whitelist toggle/mode) оркестратор
**перегенерирует** скрипт и перезапускает юнит — правила применяются
на живую, без ручного вмешательства. `ExecStop` юнита делает `ipset save`.

### Снятие

`remove_firewall` (uninstall): удаляет jump'ы из PREROUTING/INPUT/OUTPUT,
флешит и удаляет все 6 цепочек, уничтожает 4 ipset-набора, снимает ufw-
правила стека (в companion — ровно наши 4 per-IP; в standalone —
853/443/80). Ничего чужого не трогается.

---

## 14. Авторизация клиентов: ipset-whitelist и web-auth закладка

### Зачем авторизация вообще

NAT-редирект 443→8444 открывает SNI-прокси. Если бы он был доступен всем,
нода превратилась бы в открытый прокси для GeoHide-доменов. Поэтому трафик
на 8444 пускается **только с IP из ipset**; все прочие идут на cover-site.
DoT (853) по умолчанию открыт всем (с hashlimit), но может быть закрыт
whitelist'ом.

### Четыре набора и два режима

| Режим whitelist | Набор для 443→8444 | Набор для 853 | Поведение |
|---|---|---|---|
| `shared` (дефолт) | `smartdns_clients` | тот же `smartdns_clients` | DoH-авторизация открывает и DoT |
| `separate` | `smartdns_clients` | `dot_clients` | DoT-доступ выдаётся отдельно |

Запись в любом наборе живёт **24 часа** (timeout 86400 у ipset), потом
исчезает сама — доступ надо обновить (снова открыть закладку / попользоваться
DoH/DoT). Переключение shared→separate **копирует** текущие активные IP в
`dot_clients`, чтобы живые клиенты не выпали.

### Как IP попадает в набор (три пути)

1. **Web-auth закладка** — `/auth/<SECRET>`: открыли ссылку в браузере из
   нужной сети → nginx отдал страницу «Session Synchronized» и записал строку
   `web-auth-verified` в `smartdns-auth.log` → DoH-ватчер добавил IP **в
   оба** набора (базовый и DoT — независимо от режима). Это самый простой
   путь для «телефона родственника»: одна закладка на 24 часов.
2. **DoH-использование** — верифицированный успешный DoH-обмен (200 от
   движка + `application/dns-message`) → IP в базовый набор. В режиме
   shared этого достаточно и для DoT.
3. **DoT-использование** — xray пишет в access.log успешные пары
   `[dot-in -> dot-backend]` → DoT-ватчер добавляет IP в базовый набор
   (+ DoT-набор в режиме separate). Работает при выключенном whitelist:
   активные DoT-клиенты заранее получают доступ к 443→8444.

Плюс **seed при установке**: IP текущей SSH-сессии (`$SSH_CLIENT`)
молча добавляется в whitelist — владелец сразу авторизован.

### Ватчеры (как читаются логи)

Оба ватчера — self-contained Python-скрипты (`/opt/smartdns/bin/smartdns-
{doh,dot}-watcher.py`, юниты-соседи firewall-сервиса), хвостят `tail -F`
своих логов и на каждое событие делают `ipset add … timeout 86400 -exist`:

- **DoH-ватчер** разбирает `smartdns-auth.log` (формат
  `время|IP|статус|upstream|тип|байты`): пропускает всё, кроме
  `status=200 + upstream=200` и типа `application/dns-message`
  (DoH) или `web-auth-verified` (закладка), с ответом ≥ 12 байт. Приватные
  и loopback-адреса игнорируются; повторы того же IP чаще раза в минуту —
  тоже (анти-шторм от частых DoH-запросов одного клиента).
- **DoT-ватчер** разбирает `access.log` xray, ждёт строки с
  `[dot-in -> dot-backend]` и вытаскивает исходный адрес; тот же фильтр
  приватных и минутный дедуп; режим separate читает из settings.json.

Каждые ≥ 30 секунд ватчеры сохраняют `ipset save` — авторизации переживают
рестарты и ребуты (через restore в firewall-сервисе). Собственный журнал —
`/var/log/smartdns/firewall.log` (строки `[WEB-AUTH]/[DOH-AUTH]/[DOT-AUTH]
Авторизован <IP> (TTL 86400s)`).

### Управление whitelist

**Меню** (SmartDNS → 4): статус (вкл/выкл, режим, счётчики IPv4/IPv6, первые
10 адресов), пункты: добавить IP (24ч), удалить IP, очистить всё, вкл/выкл
фильтра 853, переключить режим shared/separate. Toggle и смена режима
перегенерируют firewall-скрипт и рестартуют юнит — правило 853 меняется
на живую.

**CLI**:

```bash
sudo python3 -m chimera.modules.smartdns whitelist add 198.51.100.23   # v4 или v6
sudo python3 -m chimera.modules.smartdns whitelist remove 198.51.100.23
sudo python3 -m chimera.modules.smartdns whitelist flush
sudo python3 -m chimera.modules.smartdns whitelist toggle on|off
sudo python3 -m chimera.modules.smartdns whitelist mode shared|separate
sudo python3 -m chimera.modules.smartdns whitelist status              # JSON
```

Ручная инспекция:

```bash
sudo ipset list smartdns_clients        # состав + остаток timeout у каждого
sudo ipset list dot_clients
```

---

## 15. Взаимодействие с Химерой (режим companion) — во всех деталях

### Картина целиком

Companion-режим = на одном VPS живут два независимых стека:

| | Стек Chimera | Стек SmartDNS |
|---|---|---|
| IP | основной | второй (bind_ip) |
| xray | `/usr/local/bin/xray`, `xray.service`, VLESS/REALITY на 443 основного IP | `/opt/smartdns/bin/xray`, `smartdns-xray.service`, dokodemo на `bind_ip`:8444/853 |
| nginx | `nginx.service`, vhost'ы в sites-*, заглушки (см. nginx_setup) | тот же **процесс** nginx + drop-in'ы `conf.d/smartdns.conf` и `stream-conf.d/smartdns-dot.conf` на `bind_ip` |
| панели | User Portal 9443, Subscription 9444 (основной IP) | cover-site 9443, stealth 9444 (только bind_ip + loopback) |
| DNS | AGH-стек Химеры (`adguardhome.service`, свои порты) | `smartdns-oxidns.service` на loopback 5353/8053 |
| пользователи | xray, adguard и др. | smartdns, oxidns (+ группа ssl-smartdns) |
| конфиги | `/etc/xray/`, свои state-файлы | `/etc/smartdns/`, `/var/lib/xray-installer/smartdns*/` |
| файрвол | свои правила (ufw/ipset Химеры) | цепочки SMARTDNS_* скоуплены `-d bind_ip`; ufw только per-IP |

### Чего SmartDNS в companion НИКОГДА не делает

1. **Не пишет `/etc/nginx/nginx.conf`** — только два drop-in'а и
   (единственное исключение) идемпотентный stream-include-хук: одна строка
   `include /etc/nginx/stream-conf.d/*.conf;` внутри stream-блока — или
   новый мини-блок `stream {}` в конце, если его не было. http/user/events
   не трогаются. Это тот же механизм, что уже использует singbox-модуль.
2. **Не рестартует nginx** — только `reload` (и только после `nginx -t`):
   соединения клиентов и панелей Химеры не рвутся.
3. **Не выполняет `ufw --force enable`** и не меняет дефолт-политики —
   иначе это изменило бы режим файрвола для всего VPS; открываются только
   4 per-IP правила на bind_ip.
4. **Не открывает 443** — порт основного IP принадлежит VLESS/REALITY
   Химеры; на bind_ip входящий 443 после NAT превращается в 8444/9443.
5. **Не трогает движок AGH Химеры** — в companion собственный движок
   форсирован в OxiDNS (иначе: одинаковые юниты `adguardhome.service`,
   конфликт портов и конфигов).
6. **Не трогает `xray.service`, `/usr/local/bin/xray`, `/etc/xray/`,
   пользователя xray** — полный неймспейс имён: свой бинарник, свой юнит,
   свой пользователь `smartdns`, свои конфиги в `/etc/smartdns/`.
7. **Не отключает IPv6** (баш-установщик это делал в standalone; в
   companion v6 Химеры живёт как жил).
8. **Не настраивает сеть** — второй IP вы поднимаете сами; инсталлятор
   только проверяет его наличие (preflight) и привязывается к нему.

### Разводка конфликтов: что было бы без скоупов и как решено

| Конфликт (без изоляции) | Решение в companion |
|---|---|
| NAT REDIRECT 443 без адресного фильтра перехватил бы VLESS-трафик Химеры на основном IP | каждый REDIRECT скоуплен `-d <BIND_IP>` |
| hashlimit/DROP-правила на 853 задушили бы AGH-DoT Химеры (если он слушает 853 основного IP) | правила 853 скоуплены `-d <BIND_IP>` |
| `ufw --force enable` сбросил бы режим файрвола ноды | только per-IP allow, без enable и дефолтов |
| DROP на 9443/9444 убил бы User Portal и Subscription Химеры (это их порты на основном IP) | все DROP/ACCEPT этих портов скоуплены на bind_ip |
| `xray.service`, `/usr/local/bin/xray` перезаписались бы | неймспейс: `smartdns-xray.service`, `/opt/smartdns/bin/xray` |
| `adguardhome.service` и AGH-конфиг Химеры | движок форсирован в OxiDNS, свои пути `/etc/smartdns/oxidns/` |
| nginx.conf Химеры переписался бы целиком (так делал bash в standalone) | drop-in'ы + stream-хук; `nginx -t` перед reload |
| `default_server` на 80/9443 перехватил бы чужие SNI/Host Химеры | в drop-in листенеры без default_server, строго на bind_ip |
| CF-синк увёл бы домены Химеры на второй IP | синк пишет только записи **нашего** домена; предупреждение о выборе отдельного домена — раздел 12 |
| IPv6 отключился бы вместе с Химерой | v6 не трогаем; AAAA стека удаляются, листенеры v4-only |

### port_registry: сосуществование записей

Реестр портов Химеры стал IP-осознанным вместе с этим модулем: записи
могут нести поле `bind_ip`, а детектор конфликтов понимает, что
`0.0.0.0:80` (wildcard-запись nginx Химеры) и `203.0.113.7:80` (наш
drop-in) — **не** конфликт: ядро Linux разрешает одновременный wildcard и
specific bind, specific забирает свой адрес. Поэтому:

- preflight честно пропускает порты, «занятые» wildcard-записями Химеры,
  если мы биндимся на второй IP;
- после установки в реестре видны оба соседа: записи Химеры (без bind_ip) и
  наши (с `bind_ip: 203.0.113.7`), и любые будущие модули будут получать
  конфликт ровно тогда, когда он реален.

Проверить руками:

```bash
sudo cat /var/lib/xray-installer/port_registry.json | jq '.[] | select(.service | startswith("smartdns"))'
```

### Порядок установки и что будет при перезагрузке

- **Порядок**: сначала Химера (как обычно), затем SmartDNS в companion.
  Обратный порядок тоже работает (Химера ставится поверх: её установщик не
  конфликтует с неймспейсом smartdns-*), но естественный сценарий —
  добавить DNS-ноду к живому VPN-серверу.
- **При ребуте**: `smartdns-firewall.service` (oneshot) возвращает ipset и
  цепочки, движок и `smartdns-xray` стартуют по своим зависимостям, ватчеры
  поднимаются после firewall, таймеры — по расписанию. nginx — общий,
  стартует как обычно; drop-in'ы подхватываются сами. Ничего от Химеры не
  зависит и наоборот.
- **Обновление Химеры** (`git pull` + её апдейты) не задевает стек: файлы
  не пересекаются; nginx-шаблоны Химеры пишут свои vhost'ы — наши drop-in'ы
  лежат отдельно.

### Быстрая проверка, что оба стека живы (после установки и в любой момент)

```bash
systemctl is-active xray nginx smartdns-xray smartdns-oxidns smartdns-firewall \
                    smartdns-doh-watcher smartdns-dot-watcher
sudo iptables -t nat -S SMARTDNS_PREROUTING | head   # редиректы с -d <BIND_IP>
sudo ip -4 addr show | grep <BIND_IP>                # второй IP на месте
# Химера не задета:
ss -tlnp | grep -E ':(443|9443|9444)\b'              # слушатели на своих адресах
curl -ksI https://<домен-химеры> -m 5 | head -1      # ответ основного стека
python3 -m chimera.modules.smartdns status            # статус SmartDNS
```

### Типичные companion-страхи

- «Химера перестала отвечать после установки» — почти всегда совпадение
  (например, nginx reload подхватил БЫВШУЮ битую конфигурацию). Порядок:
  `nginx -t` (должен быть OK), `systemctl status nginx xray`, при проблемах —
  `sudo python3 -m chimera.modules.smartdns uninstall` (снимает ровно наше:
  drop-in'ы, цепочки, per-IP ufw, юниты) и снова `nginx -t && systemctl reload nginx`.
- «Второй IP не отвечает» — IP не поднят в ОС (preflight бы не пропустил)
  или не маршрутизируется хостером; проверка: `ping -c3 <BIND_IP>` снаружи,
  `ip -4 addr show` изнутри.
- «Хочу поменять bind_ip» — проще всего `uninstall --purge` и установка
  заново с новым IP (стек stateless по отношению к Химере; секретный путь
  DoH сгенерируется новый).

---

## 16. Обновление стека

### Когда и как предлагается

- В **шапке меню** и в **status** — строка «Обновление: xray v… → v…; oxidns
  … → …» с подсказкой `→ [3]`, когда кэш latest (TTL 6 ч / 30 мин при сбое)
  видит более свежие release-теги, чем установленные.
- **Ручной запуск**: меню SmartDNS → `3` (Обновить компоненты) или
  `sudo python3 -m chimera.modules.smartdns update`.
- Автозапуска обновления бинарников **нет** — принцип «руками + авто-latest
  при первичной установке» (решение владельца). GeoHide/geosite обновляются
  сами по таймерам.

### Что делает update (по шагам)

1. Бэкап текущих конфигов (как при установке).
2. Резолв свежих версий всех компонентов (GitHub API).
3. Для **своего** движка и xray — сравнение `version_key`: обновляется
   только то, что строго старше; чужой движок (AGH при oxidns и наоборот)
   пропускается. Каждый компонент качается заново через download_manager и
   заменяет бинарник.
4. Переустановка geosite.dat и списка GeoHide (артефакты + routing.json с
   `xray -test`-гейтом).
5. Сертификат: если валиден (> 24 ч до конца) — не трогается; иначе —
   повторный выпуск через acme.sh (DNS-01). Так продление сертификата
   происходит при регулярных запусках `update` (собственный cron у acme.sh
   отключён `--nocron`).
6. Перегенерация конфигов xray (base) и движка, watcher/firewall-скриптов
   (настройки могли измениться), рестарт сервисов.
7. Итоговый бокс: список обновлённого («xray: v… → v…») либо «Компоненты
   актуальны».

**Чего update НЕ делает** (осознанно): не переписывает nginx-конфиг стека
(режим full/drop-in и секретный путь не меняются) и не выполняет CF-синк
(адрес стека не менялся — записи уже верны; после смены IP см. ниже).

### Смена IP-адреса ноды (runbook)

`update` берёт `server_ipv4` из settings.json. Порядок при смене адреса
(например, переезд VPS или смена второго IP):

```bash
# 1. Правим адрес стека в настройках:
sudo vi /var/lib/xray-installer/smartdns/settings.json   # server_ipv4 (и bind_ip)

# 2. Синхронизируем записи Cloudflare на новый адрес:
sudo python3 -c "
from chimera.modules import smartdns as m, smartdns_stack as st
cfg = m.load_settings() or {}
cfg.update({k: m._load_state().get(k) for k in ('mode','engine','bind_ip','domain','dot_host','whitelist_enabled','whitelist_mode')})
cfg.update(m.load_secrets())
print(st.sync_cloudflare_records(cfg, '<НОВЫЙ_IP>'))"

# 3. Перегенерируем всё, что вшивает адрес (GeoHide hosts, routing, конфиги):
sudo python3 -m chimera.modules.smartdns update
```

### Принудительная переустановка компонента

`update` не переписывает бинарник той же версии (нет force-режима, как у
B4-меню). Если бинарник повреждён — поставьте конкретный тег напрямую:

```bash
sudo python3 -c "
from chimera.modules.smartdns_stack import install_xray_binary
install_xray_binary('v26.11.9')"
sudo systemctl restart smartdns-xray
```

---

## 17. Статус и диагностика

### show_status (меню → 2 / CLI status)

Бокс «SmartDNS — Status»: режим (+bind), домен/DoT-хост, состояние восьми
юнитов (движок, xray, nginx, firewall, оба ватчера, оба таймера), порты с
пометкой bind, версии компонентов, версия стека и дата установки, строка
обновлений, срок сертификата (openssl enddate), whitelist-сводка.

### verify_dns_backend — четыре живые пробы (выполняются в конце установки)

Через `dig @127.0.0.1 -p 5353`:

| Проба | Ожидание | Что ловит |
|---|---|---|
| `example.com A` | внешний IP, ≠ SERVER_IP | движок вообще жив, апстрим работает |
| `example.com A` (повтор) | тот же ответ | кэш консистентен |
| `generativelanguage.googleapis.com A` | ровно SERVER_IP (до 15 попыток с интервалом — фильтры OxiDNS компилируются) | GeoHide-спуфинг работает |
| `generativelanguage.googleapis.com AAAA` | `NOERROR` + `ANSWER: 0` | NODATA-семантика не отдаёт v6-пустоту с ошибкой |

### Ручные проверки снаружи

```bash
# DoH (RFC 8484 GET): код 200 + content-type application/dns-message
curl -si "https://example.com/resolve/<SECRET>?dns=AAABAAABAAAAAAAAB2V4YW1wbGUK" \
  -H 'accept: application/dns-message' | head -5

# cover-site: 200 + HSTS + noindex
curl -sI https://example.com | egrep -i 'HTTP/|strict-transport|robots'

# 80-й порт: 301
curl -sI http://example.com | head -3

# web-auth закладка: 200 «Session Synchronized»
curl -s https://example.com/auth/<SECRET> | grep -o 'Session Synchronized'

# DoT с соседней машины:
kdot example.com @dns.example.com -p 853     # или: dig +tls example.com @dns.example.com
```

### Логи по назначению

| Симптом | Куда смотреть |
|---|---|
| «Не работает DoH» | `tail -f /var/log/nginx/smartdns-auth.log` (есть ли 200-е от вашего IP), `journalctl -u smartdns-oxidns -e` |
| «DoT не подключается» | `journalctl -u smartdns-xray -e`, `tail -f /var/log/smartdns/xray/access.log` (ищите `[dot-in -> dot-backend]`), `tail -f /var/log/nginx/smartdns-dot.log` |
| «Сертификат» | `/var/log/smartdns/certificate.log` |
| «Кто авторизован» | `sudo ipset list smartdns_clients`; `tail /var/log/smartdns/firewall.log` |
| «GeoHide не спуфит» | см. раздел 20 |
| «Что делал установщик» | `grep '\[smartdns\]' /var/log/chimera.log` |

---

## 18. Бэкап и откат

### Что в архиве

`create_backup` собирает tar.gz (mode 0600) в
`/var/lib/xray-installer/smartdns/backups/smartdns-<YYYYmmdd-HHMMSS>.tar.gz`:

- `settings.json`, `secrets.json`, `smartdns_state.json`;
- nginx-файлы стека: http-drop-in, stream-drop-in (и `nginx.conf` стека в
  full-режиме не входит — он восстанавливается своим `.smartdns-bak-*`);
- `/etc/smartdns/xray/conf.d` + `rules.d`, конфиг движка;
- `/etc/ssl/smartdns` (сертификат + ключ);
- `ipset-whitelist.save`.

Бэкап создаётся **автоматически** перед install, update и uninstall. Вручную:
меню → `5` → `1` или CLI `backup`.

### Откат

`rollback` распаковывает архив поверх `/` (пути в архиве — абсолютные без
корня). После отката имеет смысл перезапустить стек:

```bash
sudo systemctl restart smartdns-firewall smartdns-oxidns smartdns-xray \
                     smartdns-doh-watcher smartdns-dot-watcher
sudo nginx -t && sudo systemctl reload nginx
```

Меню → `5` показывает последние 5 архивов с размерами; `2` — откат к
последнему с подтверждением. CLI: `rollback [путь-к-архиву]` (без пути —
последний).

Отдельный случай — откат установки: при провале любого шага `install`
сам распаковывает свежий бэкап и печатает причину («Установка не удалась
(<шаг>) — откат к состоянию до установки»).

Рядом с изменяемыми nginx-файлами также остаются точечные копии
`<файл>.smartdns-bak-<ts>` (их создаёт `apply_nginx`/`_backup_file`).

---

## 19. Удаление

### Обычное удаление (файлы остаются)

```
Меню: SmartDNS → 6 → подтвердить → «Удалить и файлы?» — НЕТ
CLI:  sudo python3 -m chimera.modules.smartdns uninstall
```

Что происходит: бэкап → стоп и disable всех 12 юнитов → удаление файлов
юнитов → снятие файрвола (цепочки, ipset, наши ufw-правила) → удаление
nginx-drop-in'ов (companion: основной конфиг не трогаем, reload после
`nginx -t`) → снятие регистрации портов → state `installed: false`.

Что остаётся: бинарники `/opt/smartdns/bin`, конфиги `/etc/smartdns`,
сертификат, cover-site, ассеты, settings/secrets/state, бэкапы. Повторная
установка переиспользует их (сертификат переиспользуется, если валиден).

### Purge (снести всё)

```
Меню: SmartDNS → 6 → подтвердить → «Удалить и файлы?» — ДА
CLI:  sudo python3 -m chimera.modules.smartdns uninstall --purge
```

Дополнительно к обычному удаляются: `/opt/smartdns`, `/etc/smartdns`,
`/etc/ssl/smartdns`, `/var/www/smartdns-cover`, `/var/lib/smartdns-dns-assets`,
`/var/log/smartdns/xray`, `settings.json`, `secrets.json`, `smartdns_state.json`.
Остаются только архивы в `backups/` (последний бэкап создан перед удалением —
оттуда можно всё поднять) и системные пакеты (nginx, ufw и пр. — ставились
под нужды ноды и могли использоваться другими стеками).

### Что НЕ удаляется никогда

- Записи Cloudflare (A/AAAA остаются указывать на адрес ноды — подчистите в
  панели, если домен больше не нужен);
- правила/сервисы Химеры (uninstall трогает только неймспейс smartdns-*);
- stream-include-хук в nginx.conf (безобиден: `stream-conf.d` пуст или
  отсутствует; при желании уберите строку `include /etc/nginx/stream-conf.d/…`
  вручную и сделайте `nginx -t && systemctl reload nginx`).

---

## 20. Решение проблем

### DoH отвечает 404 на /resolve/…

- Проверьте точный путь: он печатается в итоговом боксе установки; после —
  `grep -o 'location = /resolve/[A-Za-z0-9]*' /etc/nginx/conf.d/smartdns.conf`
  (или `/etc/nginx/nginx.conf` в full-режиме).
- GET обязан нести `?dns=<base64url>` (RFC 8484), POST — заголовок
  `Content-Type: application/dns-message`. Всё остальное — сознательный 404
  (маскировка): curl без этих атрибутов тоже увидит 404.
- `curl -sI https://<домен>` должен отдавать 200 cover-site — если да, а
  DoH 404, дело в пути/методе, не в стеке.

### Android «Private DNS» не подключается

- Указывается **DOT_HOST** (например `dns.example.com`), без порта и схемы.
- Включённый whitelist 853 = новый IP без авторизации дропается: откройте
  web-auth закладку из сети телефона (`https://<домен>/auth/<SECRET>`) —
  IP попадёт в оба набора на 24 ч.
- Хостер может резать 853: проверьте снаружи `nc -vz <IP> 853` / kdig +tls.
- PTR на DOT_HOST (у хостера) помогает некоторым клиентам с строгой
  проверкой.

### «Установка не удалась (certificate) — откат»

Смотрите `/var/log/smartdns/certificate.log`: чаще всего токен без прав
DNS:Edit на эту зону или зона не в этом аккаунте. После правки — повторная
установка. (Бэкап перед установкой уже создан и распакован — система
вернулась к исходному состоянию.)

### GeoHide не спуфит (заблокированный сайт не открывается)

1. Движок: `dig @127.0.0.1 -p 5353 generativelanguage.googleapis.com A +short`
   — должен вернуть SERVER_IP. Возвращает честный IP → список/артефакты:
   `wc -l /var/lib/smartdns-dns-assets/geohide-domains.txt`; обновите
   `update-geohide`.
2. Спуфит, но сайт не открывается → клиент не авторизован: без записи в
   `smartdns_clients` 443 уходит на cover-site (это фича, не баг). Откройте
   закладку или проверьте `sudo ipset list smartdns_clients`.
3. Авторизован, но обрывы: посмотрите `tail -f /var/log/smartdns/xray/access.log`
   (SNI доходит? какая пара in→out?) и `journalctl -u smartdns-xray -e`.
4. Домен в custom-deny.txt или в безусловных исключениях (x.com, captive-
   portal детекты) — перехват отключён намеренно.

### Companion: «после установки что-то не так у Химеры»

Порядок из раздела 15 («Типичные companion-страхи»): `nginx -t` →
`systemctl status nginx xray` → `ss -tlnp` (слушатели по адресам) → при
необходимости `uninstall` (снимает только наше) → `nginx -t && systemctl
reload nginx`. Реальные повреждения от стека невозможны вне нашего
неймспейса и `-d bind_ip`-скоупов; почти всегда причина в другом изменении
на ноде.

### OxiDNS не ставится / «официальные сборки только x86_64»

Так и есть: OxiDNS выпускается только под x86_64. На ARM-ноде визард сам
переключит на AdGuardHome (standalone); в companion на ARM установка будет
заблокирована preflight'ом.

### «Компоненты актуальны», но нужно переустановить

`update` не имеет force-режима. Прямая переустановка тега — см. раздел 16
(«Принудительная переустановка компонента»).

### Движок не стартует (smartdns-oxidns failed)

- `journalctl -u smartdns-oxidns -e`: первая строка ошибки обычно
  исчерпывающая (YAML, права на ассеты, компиляция geosite).
- `ExecStartPre` уже прогнал `oxidns check` — если он прошёл, а сервис упал,
  смотрите права на `/var/lib/smartdns-oxidns` и листенеры 5353
  (`ss -ulnp | grep 5353`).

### Где лог установки

Все шаги установки/обновления дублируются в `/var/log/chimera.log`
(`grep '\[smartdns\]'`) — включая причины откатов.

---

## 21. Приложение: сводные таблицы (порты, юниты, пути, CLI)

### Порты и теги port_registry

| Порт | Протокол | Слушатель | bind_ip в companion | Тег |
|---|---|---|---|---|
| 80 | tcp | nginx | да | `smartdns_http` |
| 853 | tcp | xray `dot-in` | да | `smartdns_dot` |
| 8444 | tcp | xray `https-in` | да | `smartdns_doh` |
| 9443 | tcp | nginx TLS | да | `smartdns_web` |
| 5353 | tcp | движок | нет (loopback) | `smartdns_engine` |
| 5353 | udp | движок | нет (loopback) | `smartdns_engine` |
| 8053 | tcp | движок (DoH/AGH-панель) | нет (loopback) | `smartdns_doh_local` |
| 8853 | tcp | nginx stream | нет (loopback) | `smartdns_dot_term` |
| 9444 | tcp | nginx proxy_protocol | нет (loopback) | `smartdns_stealth` |

Итого: 8 тегов, 9 записей реестра. Порт 443 не слушается и не регистрируется
(чистый NAT REDIRECT).

### Юниты (12)

```
smartdns-xray.service            smartdns-oxidns.service | smartdns-adguardhome.service
smartdns-firewall.service        smartdns-doh-watcher.service
smartdns-dot-watcher.service     smartdns-xray-reload.path + smartdns-xray-reload.service
smartdns-geosite-update.service + .timer (04:00)
smartdns-geohide-update.service + .timer (04:05)
```

### Пути

```
/opt/smartdns/bin/                          бинарники + runtime-скрипты
/etc/smartdns/xray/{conf.d,rules.d}/        конфиги xray
/etc/smartdns/oxidns/config.yaml            движок OxiDNS
/etc/smartdns/adguardhome/AdGuardHome.yaml  движок AGH
/var/lib/xray-installer/smartdns/           settings/secrets/ipset-save/backups
/var/lib/xray-installer/smartdns_state.json state оркестратора
/var/lib/smartdns-dns-assets/               geosite + GeoHide-артефакты + custom-*
/etc/ssl/smartdns/                          fullchain/privkey
/var/www/smartdns-cover/                    cover-site
/var/log/smartdns/                          логи стека
/etc/nginx/conf.d/smartdns.conf             http-drop-in (drop-in режим)
/etc/nginx/stream-conf.d/smartdns-dot.conf  stream-drop-in
/etc/sysctl.d/90-smartdns-keepalive.conf    keepalive/mtu_probing
```

### CLI-шпаргалка

```bash
python3 -m chimera.modules.smartdns menu                        # TUI
python3 -m chimera.modules.smartdns status                      # статус
sudo python3 -m chimera.modules.smartdns install --mode companion \
    --bind-ip 203.0.113.7 --domain example.com --cf-token <TOKEN> --non-interactive
sudo python3 -m chimera.modules.smartdns preflight --mode companion --bind-ip 203.0.113.7
sudo python3 -m chimera.modules.smartdns update
sudo python3 -m chimera.modules.smartdns uninstall [--purge]
sudo python3 -m chimera.modules.smartdns backup | rollback [АРХИВ]
sudo python3 -m chimera.modules.smartdns whitelist add|remove IP
sudo python3 -m chimera.modules.smartdns whitelist flush|toggle|mode|status
sudo python3 -m chimera.modules.smartdns_stack update-geosite|update-geohide
```

### Клиентские настройки (шпаргалка для пользователей ноды)

| Платформа | Куда вписать |
|---|---|
| Android (Private DNS) | Настройки → Сеть → Private DNS: `dns.example.com` (DOT_HOST) |
| iOS / macOS (шифрованный DNS-профиль) | Профиль .mobileconfig с DoT-сервером `dns.example.com:853` или DoH `https://example.com/resolve/<SECRET>` |
| Windows 11+ | Settings → Network → DNS: DoH `https://example.com/resolve/<SECRET>` |
| Браузер (Firefox/Chrome) | Secure DNS → Custom: DoH-URL |
| Роутер (OpenWrt и пр.) | DoH/DoT-аплинк на URL/хост выше — вся сеть за роутером получает разблокировку |
| Любой stub-resolver (dnsmasq/stubby/kdig) | DoT `dns.example.com:853` или DoH-URL |

Сначала — открыть web-auth закладку `https://<домен>/auth/<SECRET>` из
нужной сети (или активно пользоваться DoH): это даст IP доступ к
SNI-прокси на 24 часа.
