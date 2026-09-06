# Chimera Project 

[![Version](https://img.shields.io/badge/version-5.0.0-blue.svg)](https://gitlab.com/netwalker071778/chimera-project)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](https://gitlab.com/netwalker071778/chimera-project/-/blob/chimera-v5/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)](https://ubuntu.com)

**Multi-Protocol Anti-DPI Installer** — мульти-протокольный установщик для обхода цензуры: VLESS REALITY/xHTTP, Hysteria2, AmneziaWG, TrustTunnel, MTProto, NaiveProxy, Mieru, FPTN, Slipgate и др. Полная автоматизация: от установки до мониторинга, с кластеризацией, балансировкой, веб-панелью и REST API.

> **Почему Chimera?** Проект вырос из простого VLESS-installer в мульти-протокольный комбайн: 9+ протоколов, 143 модуля, 25 категорий — как мифическая химера, собранная из частей разных животных. Каждая «голова» (протокол) нужна для своего сценария: VLESS — основной, AmneziaWG — устойчивый к DPI, Hysteria2 — быстрый UDP, TrustTunnel — AdGuard VPN protocol, и т.д. Если цензор блокирует один протокол, химера «выращивает новую голову». Подробное обоснование — в CHANGELOG  

```
 ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
 Chimera Project  — Multi-Protocol Anti-DPI Installer
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

> **Note:** Репозиторий также доступен на GitHub: `github.com/inferno1978/Chimera-Project` (ветка `main`, временно недоступен из-за spam-flag). GitLab (ветка `chimera-v5`) — основной источник.
>
> **⚠️ GitLab branch `chimera-v5` is a mirror only — never commit directly to it, changes will be force-overwritten on next push to `main` on GitHub.**

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
| *📺 | YouTube-маршрутизация: две новые опции для обхода ТСПУ SNI-фильтрации. **[W] YouTube→WARP** — маршрутизация через Cloudflare WARP (sendThrough + kernel table 301), интерактивный flow с авто-установкой WARP, авто-определение IP-версии (IPv4/IPv6 fallback). **[F] YouTube→RU+fragment** — TCP-фрагментация ClientHello (Xray freedom outbound с `settings.fragment`), 4 пресета (Light/Medium/Heavy/Max) + Custom, опциональная блокировка QUIC. Требует Xray 26.x+ (XTLS форк). 42 теста. |
| *📺 | **Стабильность YouTube через RU+fragment** — полная переработка на основе сверки с докой Xray v26.7.28. Решает: «видео buffering», «Shorts не грузятся», «Нет подключения при смене preset». (1) **Patch inbound sniffing** — `routeOnly=True` + `destOverride:["http","tls","quic"]` ТОЛЬКО при активном fragment (откатывается при выключении). Чинит асимметричную маршрутизацию QUIC-видео мимо fragment-правила. (2) **Безопасный sockopt** в freedom outbound (tcpKeepAlive + TFO + tcpUserTimeout) — БЕЗ `tcpCongestion="bbr"` (он ломал YouTube, требуя `modprobe tcp_bbr`). (3) **maxSplit** — новое поле fragment (недокументированное, но поддерживаемое Xray v26.x). (4) **Грейсфул-рестарт** — 500мс sleep перед `systemctl restart xray`. (5) Расширенный список YouTube-доменов (CDN variants). 16 новых тестов, всего 204 связанных теста проходят. |
| *📺 | **HOTFIX** — откат опасных изменений  (sockopt + patch sniffing). После  у пользователя YouTube снова выдал «Нет подключения к интернету». Причина: `routeOnly=True` ломал фикс v4.12.6 (freedom outbound получал IP от клиента вместо домена → `domainStrategy=UseIPv4` игнорировалась → если клиент резолвил YouTube в IPv6, dial падал). Также sockopt с `tcpFastOpen` мог фейлить `setsockopt` на VPS с `net.ipv4.tcp_fastopen=0`. Откат: убран sockopt из freedom outbound, убраны вызовы patch_inbounds_for_fragment (функции оставлены в коде с пометкой ВЫКЛЮЧЕНО). Оставлены безопасные улучшения: maxSplit, расширенный список YouTube-доменов (CDN variants), грейсфул-рестарт 500мс. Состояние: YouTube работает как в  (т.е. «работает, но нестабильно»). 11 новых тестов (включая проверку отсутствия sockopt), всего 279 связанных тестов проходят. |
| *📺 | **ВОЗВРАТ** для серверов с IPv6 connectivity. Пользователь переезжает на сервер с IPv6, где `routeOnly=True` безопасен ( freedom outbound может звонить на IPv6, не падает). Возвращено: sockopt в freedom outbound (tcpKeepAlive + TFO + tcpUserTimeout), вызовы `_youtube_patch_inbounds_for_fragment()` (routeOnly=True + destOverride[quic]). На сервере БЕЗ IPv6 — использовать QUIC block или WARP routing. Обновлены тексты TUI с предупреждением про IPv6 requirement. 59 тестов YouTube-модуля, 285 связанных тестов проходят. |
| *🛡️ | **Per-user IP whitelist** для ingress_geoip. Новый модуль `chimera/modules/user_ip_whitelist.py` — позволяет клиентам с российскими IP подключаться к VLESS на 443 при включённой блокировке входящих из РФ. Структура: `allowed_ips` в users.json → ipset `clients_wl_v4`/`clients_wl_v6` → iptables ACCEPT перед DROP. Atomic swap через `ipset swap` (без перерыва в фильтрации). **TUI**: меню → Пользователи → [6] IP whitelist. **User Portal**: карточка «🛂 Мои IP-адреса» с auto-detect текущего IP. **REST API**: GET/POST/DELETE `/api/portal/ips`. **Q1 (chicken-egg)**: User Portal на отдельном порту 8443, не подпадает под ingress_geoip DROP. **Q2 (X-Forwarded-For)**: НЕ доверяем XFF, используем `self.client_address[0]` напрямую (rest_api слушает без nginx). 40 новых тестов, 493 связанных теста проходят. |
| *🌐 | **nginx front (TLS) для User Portal + port_registry**. Два новых модуля: `chimera/modules/port_registry.py` (централизованный реестр портов с conflict detection — registry/ss/UFW/`/etc/services`) и `chimera/modules/nginx_front_portal.py` (nginx reverse-proxy с TLS для User Portal на настраиваемом порту, default 9443). nginx ставит TLS перед rest_api: `client → https://<domain>:<port> → nginx (TLS) → 127.0.0.1:8443 (rest_api)`. Сертификат Let's Encrypt переиспользуется от PARAM_DOMAIN (если нет — certbot получает новый). Auto UFW open/close через `port_registry.ufw_open_port`/`ufw_close_port` с tag-комментариями. **TUI**: меню → Веб-панель → [7] nginx front (TLS) — вкл/выкл/выбор порта/проверка конфликтов. Lifecycle: `uninstall_web_service()` автоматически удаляет nginx front. Atomic rollback при `nginx -t` fail. Security headers: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. **Паттерн port_registry** документирован для будущих рефакторингов существующих сервисов (VLESS/Hysteria2/AWG/и т.д.) — они НЕ рефакторены в этом коммите, чтобы не рисковать регрессиями. 37 новых тестов, 530 связанных тестов проходят. |
| *🔄 | **Миграция 14 сервисов на port_registry**. Все основные сервисы (WebDAV tunnel, NaiveProxy, TrustTunnel, FPTN, WDTT, Telemt MTProxy, Telemt iOS-fix, Mieru, Port hopping, AWG standalone, AWG uninstall, Subscription) переведены на централизованный `port_registry` с backward compatibility. **Новые API**: `ufw_close_port(port, proto, service, legacy_comments=[...])` — для очистки orphaned UFW-правил от старых comments; `ufw_open_port_range`/`ufw_close_port_range` — для Mieru/port_hopping. **Стратегия**: при install → `port_register` + `ufw_open_port`; при uninstall → `ufw_close_port` с `legacy_comments` (старый comment, например `"NaiveProxy"`) + `port_unregister`. **Backward compat**: orphaned UFW-правила на существующих серверах будут найдены через `legacy_comments` и удалены при следующем uninstall. **Fallback**: если port_registry недоступен — все сервисы fallback на прямой `ufw allow/delete`. **НЕ мигрированы** (намеренно): autoban/honeypot/dpi_detector (ufw **deny**, не open), singbox_ufw (своя multi-protocol логика), SSH hardening (критичная операция), VLESS port в network_setup/reconfigure (основной install flow, мигрируется отдельно). 1441 тест проходит, 0 регрессий. |
| *✅ | **Финальная миграция на port_registry**. Завершающие 4 сервиса: VLESS port (network_setup.py — SSH/HTTP/VLESS при install), VLESS reconfigure (reconfigure.py — смена порта с legacy_comments для всех старых вариантов), sing-box UFW (singbox_ufw.py — регистрация SERVICE_SINGBOX без изменения multi-protocol UFW-логики), Web Panel (rest_api.py — expose=True с SERVICE_WEB_PANEL). **Теперь ВСЕ сервисы Chimera** (кроме SSH hardening и deny-rules) используют port_registry. **Полная карта**: 17 сервисов мигрированы (VLESS install/reconfigure, sing-box, Web Panel, nginx front, WebDAV, NaiveProxy, TrustTunnel, FPTN, WDTT, Telemt MTProxy/iOS-fix, Mieru, Port hopping, AWG standalone/uninstall, Subscription). **НЕ мигрированы** (финально): SSH hardening (по указанию), emergency SSH restore, autoban/honeypot/dpi_detector (deny-rules), client_config_export (ephemeral), hybrid_addon (generic), awg_transport (remote SSH). 1945 тестов проходят, 0 регрессий. |
| *🔒 | **IP lifecycle: pin/unpin, FIFO, age-based cleanup, replace-all**. Предотвращение накопления старых IP в whitelist. (1) **Detailed формат**: `allowed_ips` теперь `[{"ip": "...", "added_at": "...", "pinned": false}]` — lazy migration старого формата (строки) при чтении. (2) **FIFO**: при достижении лимита (20) автоматически удаляется самый старый незакреплённый IP. (3) **Age-based cleanup** (cron, раз в сутки): удаляет незакреплённые IP старше N дней (default 30, настраивается). (4) **Pin/unpin**: закреплённые IP не удаляются при cleanup и FIFO — пользователь закрепляет домашний статический IP. (5) **«Заменить все»**: удаляет все IP (кроме pinned) и добавляет текущий — для быстрой смены IP. **REST API**: `POST /api/portal/ips/replace-all`, `POST /api/portal/ips/pin`, `POST /api/portal/ips/unpin`. **User Portal**: 📌 для закреплённых, кнопки Закрепить/Открепить, «🔄 Заменить все на текущий». 19 новых тестов, 684 связанных теста проходят. |
| *🌐 | **Мульти-нод конфиги подписки (Mode B)**. Новый модуль `subscription_multinode.py` — подписка отдаёт клиенту ВСЕ ноды (entry + chain-exit'ы + mirrors): `?format=clash` — полный mihomo/Clash Meta YAML по эталону проекта (DNS fake-ip+DoH сплит, TUN, sniffer, rule-providers Loyalsoldier+MetaCubeX, группы «📍 Выбор ноды»/Auto/Fallback/Balance-RR/Hash/Sticky/Weighted/Streaming/Telegram/AI, adblock+QUIC-block+RU-direct правила), `?format=singbox` — selector «🎯 Chimera» + urltest «auto» + все ноды, base64 — vless:// каждой exit-ноды (chain-UUID). GeoIP-флаги нод (ip-api, кеш 7 суток). UA-эвристика: ClashMeta/FlClash/Mihomo → clash автоматически. **User Portal**: карточка «📚 Моя подписка» (URL+QR+скачивание полных конфигов). **Admin Panel**: секция «🔁 Подписка» (per-user URL всех форматов). **TUI**: подписка → пункт 8 (вкл/выкл/авто; авто = Mode B). 23 новых теста. |
| *🛰 | **Per-user привязка сателлитов** (Mieru/NaiveProxy/Telemt/TrustTunnel/sing-box). Новый модуль `satellite_bindings.py` — единый side-table `satellite_bindings.json` с CRUD API (`set_binding`/`find_login`/`remove_binding`/`list_for_user`/`remove_user`). НЕ трогает форматы state сателлитов (TOML/JSON). Авто-сканирование логинов всех 5 сателлитов + авто-предложения привязок по совпадению имени/email-local-part/UUID (`suggest_for_user`). Приоритет в подписке: identity_map (legacy) > satellite_bindings (canon) > эвристика по имени (fallback). **TUI**: подписка → пункт 5 — авто-скан + 4 действия (принять все/выбрать вручную/снять все/legacy identity_map). **User Portal**: таб «🛰 Сателлиты» — список привязок + доступные для привязки с выпадающим списком + кнопки «Привязать/Отвязать» (с валидацией логина). **Admin Panel**: секция «🛰 Сателлиты» с таблицей всех привязок и UUID→email маппингом. Синхронизация: bind/unbind в Portal сразу обновляет подписку. **REST API**: 6 новых endpoints (user: GET sat-info/sat-suggest, POST sat-bind/sat-unbind; admin: GET sat/info, POST sat/bind/unbind). 20 новых тестов. |
| *⚠️ | **Email/имя при установке + WARNING при удалении юзера**. Баг: при удалении дефолтного «безымянного» юзера через TUI, в клиентах (Nyamebox/v2rayNG/FlClash) с импортированным его UUID подключения переставали работать с ошибкой «invalid request user id». (1) `install_prompts.py`: новые шаги [1/12] Email + [2/12] Имя при установке — email/имя администратора с валидацией; сохраняются в `PARAM_USER_EMAIL`/`PARAM_USER_NAME`; используются в users.json, User Portal, Admin Panel. (2) `users_manager.py::do_user_delete()`: WARNING + подтверждение `[y/N]` (по умолчанию N) + 4-шаговый чеклист «Действия перед удалением». Также чистит users.json + снимает привязки сателлитов (satellite_bindings.remove_user). (3) `admin_panel.py::deleteUser()`: тот же WARNING в браузере через `confirm()` с полным текстом. После удаления обновляет подписку и сателлиты. (4) `rest_api.py::DELETE /api/users/{email}`: дополнительно снимает привязки сателлитов. Работает для всех режимов: A/B, VLESS Reality / xHTTP TLS. |
| *📺 | **b4 (DPI bypass для YouTube на entry VPS)**. Новый модуль `youtube_b4.py` — интеграция с [b4 (Bye Bye Big Bro)](https://github.com/DanielLavrushin/b4), DanielLavrushin. b4 — статически слинкованный Go binary, ставится на entry VPS как systemd-сервис. Перехватывает ИСХОДЯЩИЙ TCP-трафик от Xray к YouTube CDN через iptables mangle + NFQUEUE. Применяет DPI bypass: фейковый DuckDuckGo ClientHello (DPI читает, сервер отбрасывает по pastseq) + фрагментация combo стратегией (split в середине SNI). **ТСПУ не видит SNI → пропускает → YouTube работает**. Не требует изменений в Xray config (работает поверх routing `geosite:youtube → direct`). Совместим с UFW/iptables/ingress_geoip (mangle vs filter). IPv4/IPv6 — не важно (работает на L3). 3 пресета: Default (DuckDuckGo fake + combo), Aggressive (Google fake + меньше delay), Light (только фрагментация, без fake). Discovery для автоподбора под провайдера. Health check YouTube. Web UI на порту 9700 (только локально, через SSH-туннель). **TUI**: `python3 -m chimera.modules.youtube_b4` или через основное меню → Y → B. **REST API**: 7 endpoints (`/api/b4/info`, `/api/b4/health`, `/api/b4/install`, `/api/b4/uninstall`, `/api/b4/enable`, `/api/b4/disable`, `/api/b4/preset`, `/api/b4/discovery`, `/api/portal/b4-info`). **User Portal**: таб «📺 YouTube DPI» с статусом (для юзеров). **Admin Panel**: секция «📺 b4 (YouTube DPI)» с полным управлением. Решает проблему «YouTube работает урывками / без IPv6 не работает». |

## 🔐 TrustTunnel (AdGuard VPN protocol)

**Меню:** главное → `18` · **Upstream:** https://github.com/TrustTunnel/TrustTunnel

Референсная реализация протокола AdGuard VPN на Rust (Apache 2.0, open-source с января 2026). Интеграция использует **официальный upstream-бинарник** `trusttunnel_endpoint` + `setup_wizard` (prebuilt, GPG-подписан ключом AdGuard `28645AC9...`) — НЕ форк и НЕ реимплементация. Транспорт: HTTP/2-over-TLS (TCP) и HTTP/3-over-QUIC (UDP) с мультиплексированием TCP/UDP/ICMP. Выдача доступа пользователю — через deep-link `tt://?<base64url>` (upstream TLV-формат), который встраивается в существующий self-service Telegram-бот наравне с `vless://`, `vpn://`, `hysteria2://`.

**Порт по умолчанию: `8443` (TCP + UDP).** Это отдельный порт, не 443 — порт 443 уже занят VLESS (TCP, REALITY или xHTTP) и Hysteria2 (UDP), а TrustTunnel слушает одновременно TCP и UDP на одном номере порта, не имеет SNI-dispatch и не умеет fallback. При установке конфликт проверяется через `core.check_port_used_by_other_protocol`.

Сертификаты — через существующий конвейер `ssl_certbot.obtain_ssl_cert()`. `setup_wizard` запускается БЕЗ `--cert-type` (обход upstream-дедлока ≤ v1.0.33 — ветки provided/letsencrypt гарантированно виснут в non-interactive, см. TROUBLESHOOTING.md §3), после чего `hosts.toml` перегенерируется на LE-пути. Авто-renewal — через certbot cron + deploy-hook `systemctl reload trusttunnel` (SIGHUP перезагружает `hosts.toml` без рестарта, без разрыва активных сессий).

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
git clone -b chimera-v5 https://gitlab.com/netwalker071778/chimera-project.git /opt/chimera
cd /opt/chimera
sudo python3 main.py
```

## 📚 Документация и FAQ

Подробные гайды по отдельным компонентам Chimera находятся в [`docs/faq/`](docs/faq/):

| FAQ | Описание |
|---|---|
| [`TELEMT_FAQ.md`](docs/faq/TELEMT_FAQ.md) | Telemt (MTProto Proxy) — установка, режимы Middle Proxy / Direct, xray-интеграция, SYN Limiter, фрагментация TLS |
| [`VLESS_FAQ.md`](docs/faq/VLESS_FAQ.md) | VLESS/Reality — установка, конфигурация, XOR/CDN-маскировка, разбор типовых проблем |
| [`HYSTERIA2.md`](docs/faq/HYSTERIA2.md) | Hysteria2 транспорт — UDP-протокол на базе QUIC, выбор при установке |
| [`SECURITY_BAN_FAQ.md`](docs/faq/SECURITY_BAN_FAQ.md) | AutoBan / Honeypot / IP-Ban / GeoIP Block / РФ-блокировка — пять модулей защиты от сканеров и DPI-зондов: сравнительная таблица, комбинации, диагностика, бан ASN |
| [`DNSCRYPT_FAQ.md`](docs/faq/DNSCRYPT_FAQ.md) | DNSCrypt-proxy — зашифрованный DNS: установка, конфигурация, выбор резолверов, анонимизация, ODoH/DNSSEC, принудительный DNS REDIRECT, диагностика утечек DNS |
| [`AGH_FAQ.md`](docs/faq/AGH_FAQ.md) | AdGuard Home — DNS-сервер с фильтрацией: архитектура связки Xray + AGH + DNSCrypt, плюсы и минусы, установка с нулевым даунтаймом, режимы Web UI и кастомный порт, финализация, порты и port_registry, надёжность DNS, взаимодействие с b4 (DPI-обход) |
| [`AI_ACCESS_TG_FAQ.md`](docs/faq/AI_ACCESS_TG_FAQ.md) | ИИ-агент на роутере + разблокировка Telegram — MCP/REST-доступ к b4: включение MCP-сервера, токен, три пути доступа (LAN/WAN/nginx front), firewall-правила с Source IP и персистенцией, роли «пользователь vs ИИ», живой кейс разблокировки ТГ (мост mtproto-ws, дороги: WS-edge / CF-пул Flowseal / socat / CF Worker, почему Discovery бессилен при IP-блоке), встроенные защиты b4, сравнение с VLESS-туннелями, автобан и Q&A |
| [`RU_NODE_CASCADE_FAQ.md`](docs/faq/RU_NODE_CASCADE_FAQ.md) | Выбор RU-ноды для каскада — цензурный аудит входной ноды: четыре цензора на пути (реестр оператора / ТСПУ-антитуннель / фильтры аплинка / v6-плечо), три оси профиля, два живых кейса (лицензированный оператор vs «офшорная полка» с РФ-транзитом), чек-лист аудита в 7 шагов, матрица «профиль → роль», живые и режущиеся хостеры плеча entry→exit, ловушки интерпретации детектора, Q&A |
| [`DPI_BYPASS_FAQ.md`](docs/faq/DPI_BYPASS_FAQ.md) | DPI Bypass (b4) — обход ТСПУ для YouTube и любых заблокированных ресурсов: почему b4, а не fragment/WARP, ТСПУ-ярусы (почему дома строже, чем на VPS), установка на entry VPS, пресеты, Discovery, импорт сетов, Web UI и nginx front, CRUD сетов, health check, решение проблем |
| [`GITHUB_BYPASS_FAQ.md`](docs/faq/GITHUB_BYPASS_FAQ.md) | GitHub Bypass (b4) — обход частичных блокировок GitHub (РКН и исходники): диагностика трёх режимов блока (SNI-фильтр / троттлинг / DNS-отравление), артефакты зондов на CDN-корнях, архитектура сета GitHub-Fat-v1 (combo + timestamp-фейк + DoH + эскалация на Heavy), три слоя таргетов (19 суффиксов + geosite:github на 64 домена + 87 CIDR из api.github.com/meta), установка тремя способами (MCP/Web UI/TUI), watchdog-верификация, тонкая настройка, честные ограничения (IP-душение лечится только routing→upstream) |
| [`NNM_BYPASS_FAQ.md`](docs/faq/NNM_BYPASS_FAQ.md) | NNM-Club Bypass (b4) — SNI-блок торрент-трекера за Cloudflare (полный цикл 2026-09-06): диагностика TLS_RST/TLS_DROP, разведка сателлитов (жив только nnmclub.to, зеркала — парковки/сквоттеры, таблица), Discovery → desync-fin-ttl6-c2 → сет NNM-Fat-v1 (desync-ack + pastseq + DoH против dns_poisoned + rst_protection + эскалация на NNM-Heavy-v1), почему «Discovery нашёл, но не заработало» (баг apply 1.80.x + DNS-плечо + отсутствие верификации), установка (MCP/Web UI/TUI), ограничения CF-ротации краёв |

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
├── SECURITY.md / CONTRIBUTING.md / INTEGRATION.md
├── docs/faq/                    # Подробные FAQ по компонентам Chimera
│   ├── TELEMT_FAQ.md            #   Telemt (MTProto Proxy)
│   ├── VLESS_FAQ.md             #   VLESS/Reality
│   ├── HYSTERIA2.md             #   Hysteria2 транспорт
│   ├── SECURITY_BAN_FAQ.md      #   AutoBan / Honeypot / IP-Ban / GeoIP Block / РФ-блокировка
│   ├── DNSCRYPT_FAQ.md          #   DNSCrypt-proxy — зашифрованный DNS, анти-утечки
│   ├── AGH_FAQ.md               #   AdGuard Home — DNS-сервер с фильтрацией
│   ├── AI_ACCESS_TG_FAQ.md     #   ИИ-агент на роутере + разблокировка ТГ (MCP/REST)
│   ├── RU_NODE_CASCADE_FAQ.md  #   Выбор RU-ноды для каскада (цензурный аудит)
│   ├── DPI_BYPASS_FAQ.md        #   DPI Bypass (b4) — обход ТСПУ (YouTube и любые сайты)
│   ├── GITHUB_BYPASS_FAQ.md     #   GitHub Bypass (b4) — частичные блокировки GitHub (сет GitHub-Fat-v1)
│   └── NNM_BYPASS_FAQ.md       #   NNM-Club Bypass (b4) — SNI-блок за Cloudflare (сет NNM-Fat-v1)
├── vendor/
│   └── b4/                      #   Исходники b4 v1.81.0 (апстрим DanielLavrushin/b4): src, installer, toolkit
│       └── set-artifacts/       #   Готовые сеты: GitHub-Fat-v1.json, NNM-Fat-v1.json + верификации (MCP-кейсы)
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
        │   └── users_manager, ttl_users, credential_rotation, user_fp_manager, fingerprint_manager, subscription(+subscription_multinode)
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

Смотри [TROUBLESHOOTING.md](https://gitlab.com/netwalker071778/chimera-project/-/blob/chimera-v5/TROUBLESHOOTING.md).

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

MIT — см. [LICENSE](https://gitlab.com/netwalker071778/chimera-project/-/blob/chimera-v5/LICENSE)

## ✍️ Автор

inferno1978 · [GitLab](https://gitlab.com/netwalker071778/chimera-project) · [GitHub](https://github.com/inferno1978)
