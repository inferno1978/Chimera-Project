# Chimera Project — Карта проекта

Полная карта всех модулей `chimera/modules/` (143 файла) + `_core.py`.

`_core.py` (8 093 строк) — ядро установщика: глобальное состояние, главный orchestrator `main_menu()`, `_load_state_into_globals()`, функции которые мутируют много globals (AWG, chain multi-node, install orchestration). Все модули ниже обращаются к ядру через `_core_module()` lazy binding.

---

## 1. Ядро и системные утилиты

| Файл | За что отвечает |
|---|---|
| `box_renderer.py` | Отрисовка рамок/меню в TUI — `_box_top/_box_row/_box_sep/_box_bottom/_box_item` |
| `resources.py` | Базовые генераторы и хелперы — `gen_uuid/gen_hex/gen_spiderx/get_server_ip/country_flag_emoji/get_server_country_cached/get_adaptive_value/generate_self_signed_cert` |
| `system_deps.py` | Определение пакетного менеджера (apt/dnf) + `ensure_startup_dependencies` (загрузка всех системных пакетов) |
| `tui.py` | TUI-виджеты без сторонних зависимостей — `tui_input/tui_confirm/tui_select/tui_progress/tui_form` |
| `scheduler.py` | Cron-планировщик для меню |
| `smoke_test.py` | Smoke-тест Xray после применения конфига |
| `xray_safe_apply.py` | Безопасное применение конфига с автоматическим rollback при ошибке |

---

## 2. Установка и конфигурация Xray

| Файл | За что отвечает |
|---|---|
| `xray_install.py` | Скачивание/установка Xray, генерация config.json (REALITY/xHTTP), `generate_reality_keys`, обновление, geo-файлы, автообновление (27 функций) |
| `install_prompts.py` | Интерактивные запросы параметров установки — `prompt_parameters/prompt_install_mode/prompt_protocol_mode/prompt_awg_exit_mode` |
| `nginx_setup.py` | Настройка Nginx: `create_website` (6 шаблонов), `setup_nginx_temp/final` (xHTTP TLS / AWG / REALITY+Unix-сокет), `setup_nginx_systemd_override` |
| `ssl_certbot.py` | Получение SSL-сертификата через certbot, `fix_letsencrypt_permissions`, `setup_cert_renewal`, мониторинг certbot renew (cron 2×/день) |
| `network_setup.py` | Настройка файрвола (ufw/iptables), sysctl-оптимизации (BBR+fq, conntrack, буферы), `apply_sysctl_and_limits` |
| `dnscrypt_setup.py` | Установка DNSCrypt-proxy (бинарник + конфиг + systemd-юнит + пользователь dnscrypt), `apply_dnscrypt_tuning` |
| `dnscrypt_selector.py` | Меню выбора резолверов DNSCrypt |
| `dnscrypt_advanced.py` | [RA] расширенный пресет DNSCrypt: пул 245/51 страна, анонимизация, RTT-замер (v74: синк с живым списком, кладбище, экстренный фолбэк, тест цепочки) |
| `dnscrypt_update.py` | v74: обновление/авто-обновление бинарника (timer 04:10), синк пула cron 6 ч, проверка цепочки xray→AGH→dnscrypt, общий state для всех DNS-меню |
| `geo_files.py` | Загрузка geosite.dat/geoip.dat (8 зеркал + wget fallback + ручное размещение), `setup_geo_autoupdate` (cron Sunday 03:00) |
| `backup_rollback.py` | `create_backup`/`perform_rollback` + 14 unit-тестов + `verify_connectivity` |
| `emergency_repair.py` | `do_emergency_repair` — восстановление сервера из state.json (858 строк, оркестратор полной переустановки) |
| `uninstall.py` | Полное удаление VLESS: Xray + Nginx + DNSCrypt + сертификаты + директории |

---

## 3. Пользователи и доступ

| Файл | За что отвечает |
|---|---|
| `users_manager.py` | CRUD пользователей (basic + unified manager), генерация VLESS-ссылок, QR-коды, stats screen v2 (16 функций) |
| `ttl_users.py` | Временные пользователи с TTL + blocked users, cron каждые 30 мин, авто-блокировка по истечении |
| `credential_rotation.py` | Ротация UUID (cron) + REALITY-ключей (x25519 + ShortID) + меню `_menu_rotation` |
| `user_fp_manager.py` | Управление TLS fingerprint'ами пользователей; v9: `apply_fp` отклоняет REALITY-несовместимые FP до файловых операций, гард и в TG-блоке /setfp |
| `fingerprint_manager.py` | Список поддерживаемых fingerprint'ов + `prompt_fingerprint` + REALITY-guard: `REALITY_INCOMPATIBLE_FP`/`reality_fp_warning` для random/randomized (auth-proof в session_id ClientHello не извлекается → соединение уходит на приманку; выбор — с предупреждением [y/N]) |
| `subscription.py` | Генерация подписок (subscription links) для клиентов + единый HTTP-сервер на 0.0.0.0:8443 (свой TLS от LE). **Пункт меню «7. nginx front (TLS)»** — прямой доступ по домену/IP через nginx (LE или self-signed), backend переводится на 127.0.0.1 (loopback). Регистрация через `port_registry.SERVICE_SUBSCRIPTION_NGINX`. Content negotiation: `?format=base64/singbox/clash/base64_safe` + UA-эвристика (NekoBox→singbox, ClashMeta/FlClash/Mihomo→clash, Karing→base64_safe). Хелперы для панелей: `get_subscription_base_url` / `get_portal_subscription_info` / `get_admin_subscription_info`. **Пункт меню «8. Мульти-нод конфиги (Mode B)»** — управление фичей. |
| `subscription_multinode.py` | Мульти-нодовые клиентские конфиги подписки (Mode B): реестр нод (entry + chain_nodes exits + entry mirrors) с GeoIP-флагами (ip-api, кеш 7 суток в subscription.json), `build_mihomo_config` — полный mihomo/Clash Meta YAML по эталону проекта v9 (client-configs, 2026-09-05: geodata-mode:false — .dat не качается, geox-url mmdb+asn; DNS fake-ip (fake-ip-range6 осознанно НЕ задаётся — урок v9.3/v9.4: пин /126 ронял FlClash на Android при живом IPv6 «ipnet don't have valid ip»; честная проверка IPv6-пути — SKIP_SYSTEM_IPV6_CHECK=true) + эшелоны `_AGH_DOH` (личные AGH 1-й эшелон) → Quad9/AdGuard/CF/Google + Яндекс-бутстрап; nameserver-policy на rule-set:; private.mrs; дашборд external-controller:9097 + zashboard, per-user secret из UUID; 16 групп: «📍 Выбор ноды»/Auto/Fallback/Balance-RR/Hash/Sticky/Weighted/«🇷🇺 RU-Auto»/YouTube/Streaming(+Auto)/Telegram(+Auto, по умолчанию RU-каскад)/AI(+Auto); правила adblock+ASN-рулинг+QUIC-block+RU-direct+cncidr+GEOIP RU; Mode A — MATCH,Proxy), `build_singbox_config` — все ноды как outbounds + selector «🎯 Chimera» + urltest «auto», route.final→selector + RU-сплит rulesets, `get_multinode_uris` — vless:// exit-нод (chain-UUID) в base64-подписку. Флаг: subscription.json→multinode.enabled (явный) или авто (Mode B + есть exit-ноды). Exit-URI исключаются из iOS-подписки (shadow-клиент на exit завести нельзя). Тесты: `tests/test_subscription_multinode.py` (24 теста). |
| `satellite_bindings.py` | Per-user привязка сателлитных протоколов (Mieru/NaiveProxy/Telemt/TrustTunnel/sing-box) к VLESS UUID. Единый side-table `/var/lib/xray-installer/satellite_bindings.json` (не трогает форматы state сателлитов). CRUD API: `set_binding`/`find_login`/`remove_binding`/`list_for_user`/`remove_user`. Авто-сканирование логинов всех 5 сателлитов (`scan_all_satellites`) + авто-предложения привязок по совпадению имени/email-local-part/UUID (`suggest_for_user`). Хелперы для панелей: `get_user_satellites_info`/`get_admin_satellites_info`. Приоритет резолва login в подписке: identity_map (legacy) > satellite_bindings (canon) > эвристика по имени (fallback). Тесты: `tests/test_satellite_bindings.py` (20 тестов). |

---

## 4. Маршрутизация и split-tunnel

| Файл | За что отвечает |
|---|---|
| `split_tunnel.py` | Раздельное туннелирование: РФ → direct, остальное → proxy; custom domains/IPs; меню управления |
| `ru_subnets.py` | РФ-подсети из RIPE NCC → direct routing в Xray (защита от цензора) + cron обновления |
| `as_direct.py` | AS-маршрутизация по ASN хостера/провайдера (RIPE Stat API) + cron обновления |
| `geoip_block.py` | GeoIP-блокировка через routing rules Xray (allowlist/blocklist/scanner-block) |
| `dns_rules.py` | Правила DNS для Xray |
| `ingress_geoip.py` | Блокировка входящих соединений по GeoIP через ipset/iptables |
| `ripe_file_age.py` | Проверка актуальности RIPE-файла перед включением блокировки |

---

## 5. Безопасность и баны

| Файл | За что отвечает |
|---|---|
| `autoban.py` | Авто-бан IP по ошибкам TLS handshake в access.log + embedded cron + TG-уведомления |
| `fail2ban_setup.py` | Конфигурация Fail2ban (jail для xray-reality/sshd/nginx) + Xray watchdog (systemd timer каждые 2 мин) |
| `fail2ban_manager.py` | Управление fail2ban jail'ами через меню |
| `ipban.py` | Ручной ban/unban IP-адресов через меню |
| `ipset_persist.py` | Сохранение ipset правил после ребута (systemd unit) |
| `ssh_hardening.py` | SSH hardening: смена порта, отключение паролей, AllowUsers, 2FA (TOTP через google-authenticator) |
| `honeypot.py` | Honeypot для сканеров (имитация сервисов) |

---

## 6. Мониторинг и диагностика

| Файл | За что отвечает |
|---|---|
| `diagnostics.py` | Мастер полной диагностики (14 шагов) + 30 `_diag_*` хелперов + `do_live_traffic_dashboard` + `run_split_tunnel_diagnostics` |
| `connection_audit.py` | Аудит access.log: сводка по пользователям, последние подключения, подозрительная активность, активные соединения |
| `health.py` | Health checks: xray/nginx/ssl/ports (используется другими модулями) |
| `health_report.py` | Ежедневный health-отчёт (cron 08:00) с отправкой в Telegram |
| `traffic_tracking.py` | Лимиты трафика пользователей + auto-disable при превышении (cron) |
| `traffic_history.py` | История трафика по дням (ASCII-гистограмма, снимки каждые N мин) |
| `node_health_monitor.py` | Мониторинг состояния exit-нод |
| `network_bench.py` | Бенчмарк сети (скорость/латентность до разных хостов) |
| `status_panel.py` | Статусная панель (сводка системы) |
| `standalone_screens.py` | 4 автономных экрана: `check_exit_geo` / `do_view_logs` / `do_check_domain_external` / `do_system_dashboard` |

---

## 7. Статус, скорость, реконфигурация

| Файл | За что отвечает |
|---|---|
| `quick_status.py` | CLI `--status` (быстрый статус без меню) + `do_connection_quality_test` (TTFB до Cloudflare/Google/Yandex/GitHub) |
| `speed_test.py` | Тест скорости через Cloudflare/ipinfo — Mode A (прямой) или Mode B (через exit-ноды) |
| `reconfigure.py` | Смена домена/порта без полной переустановки |
| `switch_mode.py` | Переключение Mode A↔B без переустановки (CLI `--switch-mode-a/B`) |
| `migration.py` | Полная миграция: экспорт в tar.gz.enc (AES-256-CBC) + импорт с патчем socket-пути |
| `backup_manager.py` | Плановый бэкап (cron) + CLI `--scheduled-backup` |
| `failover.py` | Failover exit-нод (watchdog каждую минуту) + auto-fallback Mode B→A при отказе всех нод |
| `mtu_tuning.py` | MTU/MSS тюнинг (бинарный ICMP DF-probe) + `do_mtu_tracepath_diag` (tracepath + ping sweep) |
| `logrotate.py` | Ротация логов Xray/nginx через logrotate |
| `config_backup.py` | Резервное копирование конфига Xray (backup_xray_config + меню) |
| `cold_boot_restore.py` | Восстановление сервисов после cold boot |

---

## 8. Telegram и уведомления

| Файл | За что отвечает |
|---|---|
| `tg_bot.py` | Telegram-бот: `_tg_notify_event`/`_tg_load`/`tg_send` + менеджер Telegram |
| `tg_nets.py` | TG-уведомления о сетевых событиях |

---

## 9. Фрагментация (TLS fragmentation)

| Файл | За что отвечает |
|---|---|
| `fragment_config.py` | Конфигурация параметров фрагментации TLS Client Hello |
| `fragment_fuzzer.py` | Фаззинг параметров фрагментации (поиск рабочих значений) |
| `fragment_guide.py` | Руководство по фрагментации для пользователя |
| `fragment_link.py` | Генерация VLESS-ссылок с фрагментацией |
| `fragment_log_viewer.py` | Просмотр логов фрагментации |
| `fragment_mux.py` | Мультиплексирование фрагментов |
| `fragment_noise.py` | Добавление шума в фрагментацию |
| `fragment_presets.py` | Пресеты фрагментации (готовые наборы) |
| `fragment_share.py` | Обмен настройками фрагментации |
| `fragment_stats.py` | Статистика фрагментации |
| `fragment_watchdog.py` | Watchdog фрагментации |

---

## 10. Hysteria2 (протокол)

| Файл | За что отвечает |
|---|---|
| `hysteria2_menu.py` | Главное меню Hysteria2 |
| `hysteria2_common.py` | Общие функции Hysteria2 (state, хелперы) |
| `hysteria2_exit_mgr.py` | Управление exit-нодой Hysteria2 |
| `hysteria2_transport.py` | Транспорт Hysteria2 поверх AWG |
| `hysteria2_balancer.py` | Балансировщик между нодами Hysteria2 |
| `hysteria2_cluster.py` | Кластерные операции Hysteria2 |
| `hysteria2_health.py` | Health-check Hysteria2 (cron) |
| `hysteria2_watchdog.py` | Watchdog Hysteria2 (cron каждые 2 мин) |
| `hysteria2_auto_update.py` | Автообновление бинарника Hysteria2 (cron ежесуточно) |
| `hysteria2_cert_mgr.py` | Менеджер сертификатов Hysteria2 (cron еженедельно) |
| `hysteria2_dpi.py` | DPI-обход Hysteria2 (авто-фолбэк) |
| `hysteria2_quality.py` | Отчёт качества Hysteria2 (с TG-отправкой) |
| `hysteria2_smoke_test.py` | Smoke-тест Hysteria2 |
| `hysteria2_traffic.py` | Статистика трафика Hysteria2 |
| `hysteria2_backup.py` | Бэкап конфигурации Hysteria2 |

---

## 11. Альтернативные протоколы

| Файл | За что отвечает |
|---|---|
| `proto_common.py` | Общие хелперы для протокольных модулей — proto_load_state/save_state, proto_ask, proto_gen_password, proto_ipt_persist, proto_get_latest/installed_version, proto_install_service, proto_show_status, proto_full_uninstall |
| `mtproto.py` | MTProto proxy (Telegram) — установка/управление |
| `mtproto_stats.py` | Статистика MTProto |
| `naiveproxy.py` | NaiveProxy — установка/управление |
| `naiveproxy_stats.py` | Статистика NaiveProxy |
| `mieru.py` | Mieru protocol — установка/управление |
| `mieru_stats.py` | Статистика Mieru |
| `fptn.py` | FPTN — L3 VPN с honeypot anti-probing (свой TUN, Protobuf поверх TLS) |
| `pq_vless.py` | Post-Quantum VLESS |
| `vk_bypass_menu.py` | Единое меню VK Whitelist Bypass (4 модуля) |
| `vkturn_menu.py` | (устарело) Меню VKTurn — теперь часть vk_bypass_menu |

---

## 12. TURN/STUN и туннели

| Файл | За что отвечает |
|---|---|
| `turntunnel.py` | FreeTurn — vk-turn-proxy + FreeTurn Android |
| `turntunnel_links.py` | Менеджер VK-call ссылок (для FreeTurn) |
| `turnable.py` | WireTurn — Turnable + WireTurn Android |
| `olcrtc.py` | OLC RTC (WebRTC-based) |
| `wdtt.py` | qWDTT — WireGuard-over-TURN (Android + Go server) |
| `wdtt_packages.py` | PackageSpec для qWDTT (Go source) |
| `wdtt_mirrors.py` | Зеркала qWDTT source |
| `csqtt.py` | CSQTT — RTP/TURN Tunnel (Android + Rust server) |
| `csqtt_packages.py` | PackageSpec для CSQTT (Rust + Zig + cargo-zigbuild) |
| `csqtt_mirrors.py` | Зеркала CSQTT source |
| `turn_packages.py` | PackageSpec для FreeTurn/WireTurn binaries |
| `turn_mirrors.py` | Зеркала для FreeTurn/WireTurn |
| `webdav_tunnel.py` | WebDAV-туннель |
| `slipgate.py` | Slipgate (обход DPI через mux) |
| `hybrid_addon.py` | Гибридный аддон (комбинация протоколов) |

---

## 13. WARP и зеркала

| Файл | За что отвечает |
|---|---|
| `warp.py` | Cloudflare WARP — 3 режима маршрутизации (full/selective/SSH-namespace) |
| `warp_curated_lists.py` | Курируемые списки доменов для WARP (itdoginfo/allow-domains) |
| `entry_mirrors.py` | Зеркала точки входа (entry mirrors) |
| `port_hopping.py` | Port hopping (сменa портов для обхода DPI) |

---

## 14. Кластер и балансировка

| Файл | За что отвечает |
|---|---|
| `cluster_ops.py` | Операции кластера (управление несколькими exit-нодами через SSH) |
| `smart_balancer.py` | Умный балансировщик (roundRobin/LeastPing/LeastLoad/Random) + auto-fallback cron |

---

## 15. Telemt (телеметрия)

| Файл | За что отвечает |
|---|---|
| `telemt_panel.py` | Веб-панель телеметрии (real-time статистика) |
| `telemt_fallback.py` | Fallback телеметрии (Middle Proxy → Direct Mode, гибрид ME) — **НЕ путать** с nginx-fallback для маскировки (тот в `mtproto.py:_setup_own_site`) |
| `telemt_self_route.py` | Self-route телеметрии |
| `telemt_warp_route.py` | WARP-route телеметрии |
| `telemt_syn_limiter.py` | SYN-лимитер телеметрии (защита от SYN-flood) |
| `telemt_mss_selector.py` | Селектор MSS телеметрии |
| `telemt_ios_fix.py` | iOS-фикс телеметрии |

> **v4.20.1 NEW** — Telemt nginx-fallback (свой домен + свой сайт): новые функции в `mtproto.py` — `OwnSiteConfig`, `_pick_local_nginx_port`, `_check_mask_backend_ready`, `_select_own_domain_submenu`, `_setup_own_site`. Параметры `mask_host`/`mask_port`/`tls_emulation` в `_write_config()`. Рефакторинг сигнатур в `nginx_setup.py` (`create_website`, `setup_nginx_final`) и `ssl_certbot.py` (`obtain_ssl_cert`) — опциональные `domain`/`port`/`socket_path` перекрывают `core.PARAM_*` без мутации глобального state. Тесты: `tests/test_telemt_nginx_fallback.py` (24 теста). См. CHANGELOG v4.20.1.

---

## 16. DPI-детекторы

| Файл | За что отвечает |
|---|---|
| `dpi_detector.py` | Детектор DPI-зондирования (анализ error.log на паттерны зондов) |
| `dpi_censor_check.py` | Проверка цензора DPI (внешние тесты, v77: автообновление апстрима Runnin4ik/dpi-detector в runtime-копию /var/lib/xray-installer/dpi-detector/) |

---

## 17. Клиентские конфиги

| Файл | За что отвечает |
|---|---|
| `client_config_export.py` | Генерация Clash Meta YAML + Sing-box JSON + VLESS-ссылки + SFTP push + one-time HTTP share с QR-кодами |
| `subscription_multinode.py` | Мульти-нод конфиги подписки (см. секцию 3) — mihomo YAML / sing-box selector/urltest / exit-URI в base64 |
| `singbox_client_rulesets.py` | Готовые `.srs` ruleset'ы для sing-box клиентских конфигов (Podkop/OpenWrt). Каталог из 8 ruleset'ов с URL'ами на `hydraponique/roscomvpn-geosite`. По умолчанию ВЫКЛЮЧЕНО — обратная совместимость 100%. При включении в TUI добавляет `route.rule_set` + `route.rules` в sing-box JSON: `category-ru.srs` → direct (Госуслуги/WB/Ozon/ДМ мимо VPN), `category-geoblock-ru.srs` → proxy (заблокированные в РФ через VPN), `whitelist.srs` → direct. Идемпотентная инъекция через `inject_route_rulesets(config, proxy_outbound_tag)`. |

---

## 18. Кэш ASN

| Файл | За что отвечает |
|---|---|
| `asn_cache.py` | SQLite-кэш префиксов ASN (RIPE Stat API) + IP→ASN lookup (ip-api.com) |

---

## 19. Вендорные модули

| Файл | За что отвечает |
|---|---|
| `_vendor/dpi_detector/` | Встроенный DPI-детектор (сторонний, MIT license) |

---

## 20. Mode B — AWG Transport

| Файл | За что отвечает |
|---|---|
| `awg_transport.py` | AWG transport (Mode B): 45 функций — install/keys/config/policy-routing/tunnel-verify, single-node + multi-node + watchdog |

---

## 21. Mode B — Chain/Nodes

| Файл | За что отвечает |
|---|---|
| `chain_nodes.py` | Chain/Nodes management (Mode B): 22 функции — chain config builders, node CRUD, health/speed tests |

---

## 22. Веб-панель, Admin Panel и User Portal

| Файл | За что отвечает |
|---|---|
| `rest_api.py` | REST API + Admin Panel + User Portal — единый HTTP-сервер (ThreadingHTTPServer, bind 127.0.0.1). Endpoints: /api/health, /api/users (CRUD), /api/rotate/*, /api/geoip/*, /api/backup, /api/portal/* (links/traffic/health/clash/singbox/password), /api/awg/* (делегирует в `awg_rest_api.py`). Rate-limit, Content-Length, HTTP/1.1, Basic Auth (secrets.compare_digest). Управление веб-панелью: install_web_service, do_manage_web_panel (меню с установкой/запуском/сменой порта/пароля/expose). do_PATCH — новый HTTP-метод для PATCH /api/awg/peers/{name}. |
| `awg_rest_api.py` | **REST API хендлеры для AmneziaWG-пиров** — встраивается в `rest_api.py` через `awg_handle_get/post/delete/patch`. Admin endpoints: GET /api/awg/status, GET /api/awg/peers, POST /api/awg/peers, DELETE /api/awg/peers/{name}, POST /api/awg/peers/{name}/regen, PATCH /api/awg/peers/{name}, GET /api/awg/peers/{name}/config, GET /api/awg/peers/{name}/qr, GET /api/awg/stats. User endpoints: GET /api/awg/my-peer, GET /api/awg/my-peer/config, GET /api/awg/my-peer/qr, POST /api/awg/my-peer/regen. Модель доступа: admin видит все пиры, user — только свой (по owner_email). Все /api/awg/* → 404 если AWG не установлен. _safe_peer_for_json фильтрует client_privkey/preshared_key/server_privkey. Валидация имени пира (path traversal protection). |
| `admin_panel.py` | HTML/CSS/JS Admin Panel — glassmorphism дизайн. Управление юзерами (создание/удаление/блокировка/пароль), ротация UUID/REALITY, бэкап. Секция AmneziaWG: статус службы, таблица пиров (имя/IP/владелец/Rx/Tx/handshake/expires/статус/действия), формы добавления и изменения пира (owner_email select из VLESS-пользователей). Кнопки: 🔒 Заблокировать, 🔑 Пароль, 🗑 Удалить. XSS-защита (esc()), credentials:same-origin в fetch. |
| `user_portal.py` | HTML/CSS/JS User Portal — анимированный интерфейс для юзеров. VLESS-ссылки + QR-коды (flexbox, рядом по центру), трафик, TTL, health, скачивание Clash/Sing-box, смена пароля. Карточка «Мой AmneziaWG» — показывается только если к юзеру привязан AWG-пир (через owner_email): QR-код, скачать .conf, перевыпустить ключи. html.escape() для name/email. |

---

## 23. Hysteria2 (15 модулей)

| Файл | За что отвечает |
|---|---|
| `hysteria2_transport.py` | Hysteria2 как транспорт exit-ноды в Mode B (QUIC/UDP туннель) |
| `hysteria2_common.py` | Общие хелперы для Hysteria2 (state, конфиг, бинарник) |
| `hysteria2_menu.py` | Меню управления Hysteria2 (установка, настройка, удаление) |
| `hysteria2_exit_mgr.py` | Управление exit-нодой Hysteria2 (сервер + клиент) |
| `hysteria2_cert_mgr.py` | Управление сертификатами для Hysteria2 (self-signed + Let's Encrypt) |
| `hysteria2_traffic.py` | Учёт трафика Hysteria2 |
| `hysteria2_health.py` | Health-чеки Hysteria2 (проверка туннеля, latency) |
| `hysteria2_watchdog.py` | Watchdog — мониторинг и авто-восстановление Hysteria2 туннеля |
| `hysteria2_auto_update.py` | Автообновление бинарника Hysteria2 |
| `hysteria2_smoke_test.py` | Smoke-тест Hysteria2 после установки |
| `hysteria2_balancer.py` | Балансировщик между несколькими Hysteria2 exit-нодами |
| `hysteria2_cluster.py` | Кластер Hysteria2 нод (multi-node) |
| `hysteria2_quality.py` | Quality-метрики Hysteria2 (packet loss, jitter) |
| `hysteria2_dpi.py` | Настройка Hysteria2 для обхода DPI (port hopping, обфускация) |
| `hysteria2_backup.py` | Бэкап/восстановление конфигурации Hysteria2 |

---

## 24. Мониторинг и watchdog

| Файл | За что отвечает |
|---|---|
| `nginx_watchdog.py` | Watchdog для Nginx — мониторинг и авто-перезапуск при падении |
| `fail2ban_manager.py` | Управление fail2ban (меню, просмотр логов, разбан) |
| `fail2ban_setup.py` | Установка и настройка fail2ban для защиты SSH/Xray |

---

## 25. AmneziaWG 2.0 Standalone (14 модулей)

Standalone AmneziaWG 2.0 — отдельный VPN-протокол (не зависит от VLESS-инфраструктуры), полный порт bivlked/amneziawg-installer v5.18.4. Доступен как пункт меню 16. Все константы имеют префикс `AWGS_*` (не конфликтуют с chain Mode B `AWG_*`). State в отдельном файле `/var/lib/xray-installer/awg_standalone_state.json`.

| Файл | За что отвечает |
|---|---|
| `awg_constants.py` | Константы, пути, defaults (префикс AWGS_* — не конфликтует с chain Mode B) |
| `awg_state.py` | State management (отдельный `awg_standalone_state.json`) — load/save/peer CRUD/owner_email миграция/find_peer_by_owner |
| `awg_presets.py` | 9 carrier-пресетов (default/mobile/Yota/Tele2 MSK+Krasnoyarsk/Таттелеком/Мегафон/Билайн/T-Mobile US) |
| `awg_hw_tuning.py` | Hardware-aware tuning (sysctl/swap/NIC) — idempotent |
| `awg_apply.py` | Apply config (syncconf без даунтайма / restart fallback), `awgs_service_status`, `awgs_show_dump` |
| `awg_standalone.py` | Главный модуль: install/uninstall/menu, конфликт-чек (chain Mode B, кросс-протокольная проверка портов через `check_port_used_by_other_protocol`) |
| `awg_peers.py` | CRUD пиров + TUI меню (add/remove/list/stats/regen/modify), `owner_email` параметр, `_validate_email` |
| `awg_qr.py` | QR-коды (terminal + PNG) + `vpn://` URI для Amnezia Client. `awgs_qr_export_peer(show_terminal=True)` — API-режим передаёт False (не печатает ключ в journal). PNG chmod 0o600, AWGS_KEYS_DIR chmod 0o700. |
| `awg_expires.py` | Временные клиенты (`--expires=1h\|7d\|30d\|4w`) + cron автоудаления |
| `awg_backup.py` | Backup/Restore с rollback при ошибке |
| `awg_cascade.py` | Каскад AWG0 (вход, РФ) ↔ AWG1 (выход, зарубеж) + split-routing по RU-сетям |
| `awg_diagnose.py` | Diagnostic + carrier-compare (kernel/sysctl/UFW/service/tunnel) |
| `awg_uninstall.py` | Полное удаление (с сохранением backup'ов опционально) |
| `awg_net_common.py` | Общий сетевой слой для AWG-модулей: NAT/MASQUERADE + sysctl + iptables-idempotency. `iptables_ensure` (idempotent -A через -C check), `build_nat_rule_args`/`build_nat_idempotent_shell`/`build_nat_cleanup_shell` (IPv4), `build_nat6_*` (IPv6), `build_sysctl_lines` (per-interface rp_filter=2 loose mode), `detect_wan_iface`. Используется из `awg_standalone.awgs_setup_nat_and_routing` и `awg_transport._awg_server_conf_text` (PostUp/PostDown). |

**Дополнительно:** `awg_rest_api.py` (REST API хендлеры для веб-панели) — см. секцию 22.

---

## Структура каталогов

```
chimera/
├── _core.py              (8 093 строки — ядро, главный orchestrator)
├── __init__.py           (version = "5.0.0")
├── __all_exports.py      (реэкспорт API для программного доступа)
└── modules/              (143 модуля)
    ├── __init__.py
    ├── _vendor/          (вендорные модули)
    │   └── dpi_detector/
    └── *.py              (143 файла, см. группы выше)

vendor/                   (вендор внешних проектов — вне python-пакета)
└── b4/                   (исходники b4 v1.81.0, апстрим DanielLavrushin/b4)
    ├── src/              (Go-исходники: 561 файл, 248 тестов — engine,
    │                      nfq/tun/tproxy, discovery, mcp-сервер в src/http)
    ├── installer/        (установщик ОС-пакетов)
    ├── toolkit/          (утилиты)
    └── set-artifacts/    (готовые сеты: GitHub-Fat-v1.json, NNM-Fat-v1.json
                           + JSON-верификации обоих MCP-кейсов)
```

## Паттерн доступа к ядру

Все модули получают доступ к `_core.py` через `_core_module()` lazy binding:

```python
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")

def some_function():
    core = _core_module()
    info = core.info
    _run = core._run
    # ...
```

Это позволяет избежать циклических импортов и работать как из интерактивного режима, так и из cron.

## CLI entry points (в main.py)

| Флаг | Что вызывает |
|---|---|
| `--status` | `do_quick_status()` |
| `--switch-mode-a` / `--switch-mode-b` | `switch_mode_ab()` |
| `--scheduled-backup` | `_scheduled_backup_run()` |
| `--update-ru-subnets` | `_ru_subnets_cli_update()` |
| `--update-as-direct` | `_as_direct_cli_update()` |
| `--autoban` | `_autoban_run_once()` |
| `--ttl-check` | `_ttl_check_and_expire()` |
| `--clear-asn-cache` | `_asn_cache_delete()` / `ASN_CACHE_DB` |
| `--tg-event` | `_tg_notify_event()` |
| `--dpi-check` | `_dpi_run_once()` |
| `--smart-balance` | `_smart_balancer_run_once()` |
| `--pinned-fallback-check` | `_pinned_node_check_and_fallback()` |
| `--h2-*` | Hysteria2 CLI entry points (12 шт.) |
| `--ingress-geoip-update` | ingress geoip update |
| `--telemt-panel-geoip-update` | telemt panel geoip update |
