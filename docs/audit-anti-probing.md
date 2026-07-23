# Audit: anti-probing behaviour (Phase 0)

**Дата:** 2026-07-21
**Метод:** статический аудит кода Chimera (репозиторий `gitlab.com/netwalker071778/chimera-project`).
**Цель:** для каждого протокола зафиксировать, что видит внешний активный пробер (DPI / ТСПУ), который открывает TCP/UDP-соединение на порт протокола **без валидного клиента** — не тот SNI, не тот сертификат, не тот handshake, просто "открыл порт и ждёт".
**Ограничения:** фаза 0 — без изменений кода, без тестирования на живом сервере.

Каждая строка в таблице сопровождается конкретной ссылкой `file:line` на код Chimera. Записи без ссылки не допускаются.

---

## 1. Сводная таблица — 17 протоколов × 6 столбцов

| # | Протокол | Порт(ы) / транспорт | TLS-termination | Поведение при НЕ-своём SNI / чужом клиенте | Сертификат | Общий порт с другим протоколом? | Заметки в коде |
|---|---|---|---|---|---|---|---|
| 1 | **vless_state** (база, xray+nginx) | TCP:443 (`nginx_setup.py:646,727`); также TCP:80 для ACME (`nginx_setup.py:761`) | **nginx** (`nginx_setup.py:757-801`, классический REALITY через Unix-сокет) — см. также xHTTP-ветку `nginx_setup.py:580-668` и AWG-ветку `nginx_setup.py:670-707` | **`ssl_reject_handshake on;` на `default_server`** для nginx ≥ 1.19.4; fallback на `return 444` для старых nginx (`nginx_setup.py:743-755`, 794-800). Это мгновенный TLS-abort (RST после ClientHello). Для AWG-режима (`nginx_setup.py:670-707`) — nginx слушает только :80 (HTTP→HTTPS редирект), :443 держит Xray напрямую | Let's Encrypt, общий для базового домена (`nginx_setup.py:774-775`) | Да, :443 — см. строку 17 (sing-box VLESS-WS-CDN) и строку 11 (ShadowTLS/AnyTLS через SNI-dispatch) | "Default server: reject all other SNI" — `nginx_setup.py:644, 794` |
| 2 | **hysteria2** | UDP:443 (или диапазон UDP-портов, default `[443]`) — `hysteria2_exit_mgr.py:166, 339, 402` | **сам протокол** (Hysteria2 binary, `hysteria2_exit_mgr.py:213` `hysteria server --config /etc/hysteria/config.yaml`) — не nginx | **Decoy через нативный `masquerade: type: proxy → url: https://news.ycombinator.com, rewriteHost: true`** — `hysteria2_exit_mgr.py:176-180`. Сервер сам проксирует "чужой" QUIC-handshake на реальный сайт; наблюдатель видит настоящий TLS-сертификат HN, не отказ и не голый QUIC | Let's Encrypt через certbot, fallback на self-signed (`hysteria2_exit_mgr.py:250-264`, `hysteria2_cert_mgr.py:141-160`) | Да, **порт 443 UDP конфликтует с vless_state :443 TCP по семейству протокола** (UDP vs TCP — разные сокеты, ядро допускает одновременно). Не проверяется как конфликт — `hysteria2_exit_mgr.py` только открывает UDP-порт через `open_udp_ports` | Masquerade — встроенный механизм Hysteria2, не отдельный decoy-модуль |
| 3 | **mieru** (mita) | TCP или UDP, диапазон 2012-2022 (`mieru.py:142-143`, `_DEFAULT_PORT_START/_END`); также одиночный порт (`mieru.py:414-418`) | **сам протокол** (mita binary, `mieru.py:131-136`); mTLS — **взаимная** аутентификация, клиент обязан предоставить cert, выведенный из password | **mTLS обрывает handshake на этапе mutual auth.** Никакого decoy-контента: при невалидном client-cert TLS-handshake падает стандартным `tls: handshake failure` (`autoban.py:4`, `fail2ban_setup.py:107` — failregex матчит `TLS handshake failed`). Decoy не предусмотрен. mita работает по IP, без домена (`mieru.py:11`, 38) | Внутренний CA mita, cert генерируется самим mita; в `server.json` только `users` (username+password), никаких `certificate` полей (`mieru.py:425-440`) | Нет — порт-рейндж 2012-2022 не пересекается ни с чем | "Не требует домена — работает по IP" — `mieru.py:11`; "mTLS — взаимная аутентификация клиента и сервера" — `mieru.py:1418` |
| 4 | **naiveproxy** | TCP:443 (`naiveproxy.py:145`, `_DEFAULT_PORT = 443`) | **caddy-naive** (`naiveproxy.py:127-134`, 403-426) — отдельный Caddyfile, не nginx | **Decoy через `probe_resistance {probe_secret}` + `file_server` с фейковым сайтом** (`naiveproxy.py:413, 415-417`). Без `probe_secret` в запросе Caddy отдаёт статику из `/var/www/naive-fake/index.html` — кастомный HTML "Welcome / This site is under maintenance" (`naiveproxy.py:556-561`). Это **осмысленный decoy-контент** | Свой: Caddy `tls { on_demand }` по умолчанию (`naiveproxy.py:397`), либо явный `tls cert key` если переданы (`naiveproxy.py:394-395`) | **Да, :443 — конфликтует с vless_state TCP:443.** Разруливается тем, что naiveproxy ставит свой `caddy-naive` отдельно от nginx (`naiveproxy.py:133`), и пользователь обязан выбрать: либо nginx+VLESS на :443, либо caddy-naive на :443. Явной блокировки установки обоих одновременно в коде нет — это instal-time конфликт портов (через `core.check_port_used_by_other_protocol`) | "probe resistance → фейковый сайт для незнакомых" — `naiveproxy.py:15, 1483`; "probe_resistance маскирует это под редирект на fake-site" — `naiveproxy.py:387` |
| 5 | **wdtt** (qWDTT) | UDP:56000 (DTLS-вход), UDP:56001 (внутренний WG) — `wdtt.py:19-20`; default `_DEFAULT_DTLS_PORT` через `state.get("dtls_port", ...)` (`wdtt.py:567, 846`) | **сам протокол** (wdtt-server binary, `wdtt.py:797` `-listen 0.0.0.0:{dtls_port}`); WRAP RTP AEAD/ChaCha20-Poly1305 поверх DTLS 1.2 (`wdtt.py:14`) — **не TLS**, DTLS | **Не применимо в терминах SNI** — DTLS не имеет SNI. При невалидном WRAP-handshake wdtt-server просто отбрасывает пакет; наблюдатель получает UDP timeout (никакого RST в UDP нет по определению). Decoy не предусмотрен | Без сертификата в TLS-смысле — DTLS-handshake WRAP использует ключи, выведенные из пароля через HKDF (`wdtt.py:32`) | Нет — порт 56000 UDP уникален, 56001 зарезервирован под внутренний WG | "WireGuard over TURN Tunnel" — `wdtt.py:4`; трафик маскируется под медиа-поток звонка через TURN ВКонтакте (`wdtt.py:13-18`) — это **естественная маскировка на уровне оператора**, не server-side decoy |
| 6 | **turntunnel** (vk-turn-proxy / FreeTurn) | UDP:56000 (`turntunnel.py:18, 109`, `_DEFAULT_LISTEN_PORT = 56000`) | **сам протокол** (vk-turn-proxy binary, `turntunnel.py:332` `-listen 0.0.0.0:{listen_port}`); DTLS 1.2 поверх STUN ChannelData (`turntunnel.py:13`) — **не TLS**, DTLS | **Не применимо в терминах SNI** — DTLS/STUN не имеют SNI. При невалидном STUN/DTLS-пакете vk-turn-proxy молча отбрасывает; наблюдатель видит UDP timeout | Без сертификата — DTLS-handshake выполняется внутри TURN-сессии ВКонтакте, не на VPS-порту | Нет — 56000 UDP уникален. **56001 занят Turnable** (`turntunnel.py:56000`, `turnable.py:56001`) | "Трафик выглядит как медиа-звонок" — `turntunnel.py:15`; маскировка на уровне TURN-оператора, не server-side decoy |
| 7 | **turnable** (WireTurn) | UDP:56001 (Turnable server) + TCP:12767 (Xray inbound на loopback) — `turnable.py:118-119` | **сам протокол** (Turnable binary, `turnable.py:467-501`); WebRTC DTLS поверх TURN (`turnable.py:14`); Xray inbound на 127.0.0.1 — **plain TCP, без TLS** (`turnable.py:291-304`, 32) | **Не применимо в терминах SNI** — Turnable слушает UDP:56001 для WebRTC DTLS; Xray inbound на 127.0.0.1:12767 **не доступен извне** (loopback). При невалидном WebRTC-handshake Turnable отбрасывает; наблюдатель видит UDP timeout | Без сертификата TLS — WebRTC DTLS; Xray-инбаунд plain | Нет — 56001 уникален | "WebRTC DTLS поверх TURN" — `turnable.py:14`; маскировка на уровне TURN ВКонтакте |
| 8 | **olcrtc** | **Нет listening-порта на VPS** — серверная часть подключается к WebRTC-комнате (Jitsi/Яндекс.Телемост/WB Stream) как participant (`olcrtc.py:4-7, 9-15`) | **Внешний carrier** (Jitsi и т.п.) — Chimera не терминирует TLS для olcRTC | **Не применимо** — нет listening-порта, нечего пробовать. Каждая "линк" — отдельный outbound WebRTC-процесс (`olcrtc.py:10-15`); SOCKS5 поднимается на стороне клиента (`olcrtc.py:465-466, 620`) | Не применимо — TLS терминирует WebRTC-carrier | Нет | "olcRTC не умеет 'один сервер — много пользователей одним портом'" — `olcrtc.py:10`; "TCP-over-WebRTC: маскирует трафик под звонок в Jitsi" — `olcrtc.py:817` |
| 9 | **slipgate** | UDP:53 (DNSTT/NoizDNS/Slipstream/VayDNS) или TCP:443 (NaiveProxy/StunTLS) — `slipgate.py:14-44` | **Зависит от под-транспорта:** DNSTT — сам slipgate-бинарь; NaiveProxy — Caddy+Let's Encrypt; StunTLS — самоподписанный TLS (`slipgate.py:815, 820, 827`) | **Зависит от под-транспорта:** DNSTT — DNS-протокол, не SNI; NaiveProxy — см. строку 4 (probe_resistance + fake site); StunTLS — SSH over TLS+WS, при чужом SNI TLS-handshake падает стандартно (никакого decoy). Все под-транспортники — внешние бинарники от авторов SlipGate, **Chimera только вызывает `install.sh`** (`slipgate.py:51, 130`) | StunTLS — самоподписанный (`slipgate.py:815`); NaiveProxy — Let's Encrypt через Caddy (`slipgate.py:820`); DNSTT — Curve25519 без TLS-сертификата | Да, :443 — StunTLS/NaiveProxy конфликтуют с vless_state, если установлены одновременно | "SlipGate — DNS-туннельный транспорт для обхода полных блокировок" — `slipgate.py:4-5`; warnings отсутствуют — модуль делегирует slipgate-install.sh |
| 10 | **fptn** | TCP:443 (`fptn.py:153`, `_DEFAULT_PORT = 443`) | **сам протокол** (fptn-server binary, `fptn.py:647-664` `--server-crt=${SERVER_CRT}`); Protobuf-туннель поверх TLS (`fptn.py:4, 18`) | **Decoy через honeypot-прокси на живой контент:** при невалидном TLS-handshake (не FPTN-клиент) сервер **сам проксирует коннект на настоящий домен** (`DEFAULT_PROXY_DOMAIN=www.wikipedia.org`, `fptn.py:155`) или на SNI из `ALLOWED_SNI_LIST` (`fptn.py:656, 701`). Сканер видит живой сайт, а не отказ или голый TLS (`fptn.py:9-13`, 1398-1403) | **Самоподписанный** RSA 4096, 10 лет (`fptn.py:425-438` `openssl req -x509`); md5-fingerprint используется в клиентском токене (`fptn.py:440-446`) — pin по fingerprint, не через CA | **Да, :443 конфликтует с vless_state и naiveproxy.** Разруливается через `core.check_port_used_by_other_protocol` (см. install flow) | "сервер САМ проксирует этот коннект на настоящий домен ... сканер видит живой сайт, а не отказ или голый TLS-хэндшейк" — `fptn.py:9-13`; "DEFAULT_PROXY_DOMAIN / ALLOWED_SNI_LIST" — `fptn.py:10, 656, 701, 1398-1403` |
| 11 | **trusttunnel** | TCP:8443 + UDP:8443 одновременно (`trusttunnel.py:152`, `_DEFAULT_PORT = 8443`; README.md:75) | **сам протокол** (Rust-бинарь trusttunnel_endpoint, `trusttunnel.py:5, 1819`); HTTP/2-over-TLS или HTTP/3-over-QUIC (`trusttunnel.py:11, 1824`) | **Никакого decoy/fallback.** При чужом SNI/невалидном Basic-auth сервер отдаёт стандартный TLS-error / закрывает соединение. Явное признание в коде: "на одном номере порта, не имеет SNI-dispatch и не умеет fallback" (`trusttunnel.py:1836`, а также `README.md:75`) | Let's Encrypt через `ssl_certbot.obtain_ssl_cert()` с fallback на self-signed (`trusttunnel.py:1354-1378`, 1514-1520) | Нет — порт 8443 выбран специально, чтобы не конфликтовать с :443 vless_state/hysteria2 (`trusttunnel.py:1834`, README.md:75) | **Прямое самопризнание:** "TrustTunnel слушает одновременно TCP (HTTP/2) и UDP (HTTP/3) на одном номере порта, не имеет SNI-dispatch и не умеет fallback." — `trusttunnel.py:1836`; продублировано в `README.md:75` и `CHANGELOG.md:1412` |
| 12 | **singbox: shadowtls** | TCP:8443 loopback (listen `127.0.0.1:8443`) — `singbox_common.py:49`, `singbox_config.py:120` | **сам протокол** (sing-box inbound ShadowTLS v3, `singbox_config.py:117-130`). **Внешний listen — только через nginx SNI-dispatch** (`singbox_nginx.py:16-18, 161-213`); без SNI-dispatch — на loopback, не доступен извне | **Проксирует TLS-handshake целиком на реальный внешний сервер** (по умолчанию `www.cloudflare.com:443`) — `singbox_config.py:123-125`. Наблюдатель видит **настоящий сертификат реального сайта**, не свой sing-box cert. Локальный `tls`-блок в inbound НЕ генерируется ни при каких условиях (`singbox_config.py:104-105, 130-132`). Это самая сильная форма decoy | Не используется локально — `singbox_config.py:130-132` явно отказывается добавлять `tls`-блок; cert_path/key_path игнорируются | Да, **:443 через SNI-dispatch** — при включённом SNI-dispatch делит TCP:443 с AnyTLS и vless_state Reality (`singbox_nginx.py:14-18`) | "ShadowTLS v3 — принимает TLS-handshake к маскировочному домену, после handshake передаёт трафик на trojan-in через detour" — `singbox_config.py:15-16`; "наблюдатель видит настоящий сертификат реального сайта" — `singbox_config.py:102-103` |
| 13 | **singbox: anytls** | TCP:8444 loopback (listen `127.0.0.1:8444`) — `singbox_common.py:50`, `singbox_config.py:191` | **сам протокол** (sing-box inbound AnyTLS, `singbox_config.py:188-208`); **внешний listen — только через nginx SNI-dispatch** (`singbox_nginx.py:17`) | Без SNI-dispatch — не доступен извне (loopback). **С SNI-dispatch:** при чужом SNI nginx stream передаёт трафик на `default_backend` = Reality backend Xray (`singbox_nginx.py:174, 194, 232, 248-250`). Любой чужой SNI уходит в Xray REALITY, который сам сделает fallback (отдаст REALITY-сертификат). Своего decoy-контента AnyTLS не имеет | Сертификат любой: self-signed или Let's Encrypt (`singbox_config.py:198-204`, `singbox_common.py:498-532`); формат `certificate_path/key_path` (string, не array) — `singbox_config.py:203` | Да, **:443 через SNI-dispatch** — делит с ShadowTLS и vless_state Reality | `"anytls"` fallback disabled — фикс HYDRA `anytls/plugin.py:18-28` (`singbox_config.py:153-155`) |
| 14 | **singbox: tuic** | UDP:8443 (default), либо UDP:443 (alternative `DEFAULT_PORT_TUIC_ALTERNATIVE = 443`) — `singbox_common.py:51, 55`; listen `::` (все интерфейсы) — `singbox_config.py:233` | **сам протокол** (sing-box inbound TUIC, `singbox_config.py:231-247`); QUIC, не пересекается с TCP:443 (`singbox_nginx.py:20`) | **Без decoy.** При невалидном QUIC-handshake sing-box отбрасывает пакет; наблюдатель видит UDP timeout. Никакого masquerade-блока в конфиге **нет** (ср. с hysteria2, где есть нативный `masquerade:`) | Свой сертификат tuic.crt/tuic.key (`singbox_config.py:244-247`) — Let's Encrypt или self-signed | Да, **UDP:8443 делит номер порта с trusttunnel UDP:8443** (TCP/UDP — разные сокеты, не конфликтует на уровне ядра, но **логически та же пара "ip:port"**). Альтернативный UDP:443 — делит с hysteria2 | Не помечено в коде как проблема; `singbox_common.py:51` показывает default 8443, `55` — alternative 443 |
| 15 | **singbox: vless_ws_cdn** | TCP:8443 (default `DEFAULT_PORT_VLESS_WS_CDN`, но переопределяется под CDN: Gcore/Bunny=8443, Cloudflare=8080/2052/2082/2083/2086/2095) — `singbox_common.py:121`, `singbox_config.py:295` | **CDN** (Cloudflare/Gcore/Bunny.net) — sing-box слушает **plain WebSocket без TLS** (`singbox_config.py:275-308`). CDN↔origin = HTTP, не HTTPS | **Без TLS на origin-порту.** При прямом TCP-подключении на origin:8443 наблюдатель видит plain HTTP с `Upgrade: websocket` — никакого TLS-handshake вообще. Это **анти-decoy**: любой пробер мгновенно понимает, что перед ним WS-endpoint, а не веб-сервер. CDN-allowlist ограничивает доступ по IP CDN (`singbox_config.py:651-658`), но это не decoy | Не используется — TLS терминирует CDN (`singbox_config.py:275-308`, `singbox_common.py:96-97, 144-217`) | Да, порт 8443 делится с ShadowTLS TCP и TUIC UDP (разные протоколы L4) | "TLS живёт только на грани CDN — sing-box слушает plain WS. Добавление 'tls' сюда было бы мёртвым JSON-полем" — `singbox_config.py:275-276`; "CDN терминирует TLS, origin слушает plain WS" — `singbox_config.py:308` |
| 16 | **subscription** | TCP:8443 (default `DEFAULT_PORT`, может переопределяться) — `subscription.py:164, 1051` | **сам модуль** (`subscription.py:59, 1051` `ThreadingHTTPServer` + `ctx.load_cert_chain`) | **Никакого decoy.** На любой путь, не матчащий `^/sub/([0-9a-f]{24})/?$`, отдаётся **`404 Not Found`** (`subscription.py:940, 959, 973, 1359`). Никакого fallback-контента. На чужой SNI — обычный TLS-handshake с сертификатом домена (см. след. столбец), затем 404 на любой путь | Сначала Let's Encrypt (через `_find_cert_pair`, `subscription.py:1022-1038`), при отсутствии — **fallback на сертификат Hysteria2** из state.json. Если обоих нет — startup warn, "поставьте сертификат или проксируйте через nginx с TLS" (`subscription.py:1056-1059`) | Да, **:8443 делит с trusttunnel TCP:8443 и sing-box ShadowTLS TCP:8443**. Без явной проверки — `subscription.py:1454-1469` добавил `check_port_used_by_other_protocol` только в install-flow, но default 8443 совпадает с trusttunnel (`subscription.py:1455-1457`) | "напрямую (без внешней зависимости от nginx — топология веб-морды перед Reality на 443 у каждого инсталла своя и её лучше не трогать вслепую)" — `subscription.py:33-34` |
| 17 | **admin-панель / user portal** (`rest_api.py`, сервис `vless-web`) | TCP:8443 (default `DEFAULT_WEB_PORT`) — `rest_api.py:71, 118`; listen `0.0.0.0` при `expose=True`, иначе `127.0.0.1` — `rest_api.py:1817, 1922-1928` | **НЕТ TLS ВООБЩЕ.** Голый `http.server.ThreadingHTTPServer` (`rest_api.py:52, 1817`). В коде явно написано: "Используйте reverse-proxy (nginx) с TLS или SSH-туннель" — `rest_api.py:1824` | **Никакого decoy, никакого TLS.** На любой неизвестный путь → `404 Not Found` (`rest_api.py:1156-1157, 1359, 1695, 1768, 1789`). На `/admin/` и `/portal/` без basic-auth → `401 Unauthorized` (`rest_api.py:1138-1140`). На `/api/health` без auth → `200` с health-info (`rest_api.py:1183-1184`). **Пробер видит голый HTTP-сервер с типичным паттерном ответов Python stdlib** — это легко идентифицируется | **Не предусмотрен.** TLS делегируется внешнему reverse-proxy (`rest_api.py:1822-1824`), но конфигурации reverse-proxy в модуле нет — пользователь должен настроить nginx сам | Да, **:8443 делит с subscription, trusttunnel, sing-box ShadowTLS**. `rest_api.py:71` `DEFAULT_WEB_PORT = 8443` — конфликт по умолчанию | "⚠️ Используйте reverse-proxy (nginx) с TLS или SSH-туннель" — `rest_api.py:1824`; "ВНИМАНИЕ: веб-панель открыта наружу на 0.0.0.0:{port} без TLS!" — `rest_api.py:1926-1928` |

---

## 2. Явные признания в коде об отсутствии fallback/decoy

Цитаты с `file:line`, в которых разработчики Chimera сами фиксируют пробелы в anti-probing защите.

### 2.1. TrustTunnel — отсутствие SNI-dispatch и fallback

> `chimera/modules/trusttunnel.py:1836`
> ```
> _box_info("на одном номере порта, не имеет SNI-dispatch и не умеет fallback.")
> ```

Дословное цитирование из функции `_guide_overview` (UI-гайд). Контекст — `trusttunnel.py:1832-1836`:
```
_box_row(f"  {BOLD}{WHITE}Порт 8443 (TCP+UDP):{NC}")
_box_info("Отдельный порт, НЕ 443 — 443 занят VLESS (TCP) + Hysteria2 (UDP).")
_box_info("TrustTunnel слушает одновременно TCP (HTTP/2) и UDP (HTTP/3)")
_box_info("на одном номере порта, не имеет SNI-dispatch и не умеет fallback.")
```

Дублирование в README:
> `README.md:75`
> ```
> **Порт по умолчанию: `8443` (TCP + UDP).** Это отдельный порт, не 443 — порт 443 уже занят VLESS (TCP, REALITY или xHTTP) и Hysteria2 (UDP), а TrustTunnel слушает одновременно TCP и UDP на одном номере порта, не имеет SNI-dispatch и не умеет fallback.
> ```

Дублирование в CHANGELOG:
> `CHANGELOG.md:1412`
> ```
> **Порт по умолчанию `8443` (TCP+UDP)** — отдельный порт, не 443 (443 занят VLESS TCP + Hysteria2 UDP; TrustTunnel не имеет SNI-dispatch и не умеет fallback).
> ```

**Следствие для пробера:** любой чужой TLS-клиент, открывший TCP:8443 на сервере с TrustTunnel, видит стандартный TLS-handshake с сертификатом Let's Encrypt для домена TrustTunnel. После handshake — 401/403/404 от Rust-httpd. Никакой decoy-стратегии нет; fingerprint сервера уникален и опознаваем.

### 2.2. Subscription — без декоя, голый 404

> `chimera/modules/subscription.py:33-34`
> ```
> напрямую (без внешней зависимости от nginx — топология веб-морды перед
> Reality на 443 у каждого инсталла своя и её лучше не трогать вслепую).
> ```

Модуль сознательно отказывается от интеграции с nginx — каждый инсталл "имеет свою топологию", и авторы боятся её сломать. Побочный эффект: никакой `default_server`-логики, никакого `ssl_reject_handshake`, никакого decoy-сайта — только голый Python `ThreadingHTTPServer` с 404 на всё неизвестное (`subscription.py:940, 959, 973, 1156-1157, 1359`).

### 2.3. Admin-панель / User Portal — без TLS

> `chimera/modules/rest_api.py:1822-1824`
> ```
> print("[VLESS Web] ⚠️  Используйте reverse-proxy (nginx) с TLS или SSH-туннель.")
> ```
> `chimera/modules/rest_api.py:1926-1928`
> ```
> f"ВНИМАНИЕ: веб-панель открыта наружу на 0.0.0.0:{port} без TLS! "
> ```

Модуль явно признаёт, что сам по себе он не имеет TLS — это делегируется внешнему reverse-proxy, конфигурирование которого не входит в модуль. При `expose=True` (опция "Открыть панель наружу") порт 8443 отдаётся в интернет голым HTTP — это означает, что **проберу не нужен даже TLS-handshake, чтобы идентифицировать сервис** (стандартный `GET /` отдаёт `401 WWW-Authenticate: Basic realm="Admin"` от Python stdlib, что легко опознаётся).

### 2.4. VLESS-WS-CDN — origin без TLS

> `chimera/modules/singbox_config.py:275-277`
> ```
> поля "tls" НИ ПРИ КАКИХ УСЛОВИЯХ. TLS живёт только на грани CDN — sing-box
> слушает plain WS. Добавление "tls" сюда было бы мёртвым JSON-полем.
> ```

Это сознательное архитектурное решение: origin-порт (8443/8080/...) слушает plain WebSocket без TLS. Если CDN-allowlist не сработал или пробер достучался напрямую до origin-IP — он видит **plain HTTP с `Upgrade: websocket`**, что однозначно идентифицирует прокси-инфраструктуру. Это **анти-decoy**: защита основана исключительно на IP-allowlist CDN (`singbox_config.py:651-658`), без decoy-слоя на самом origin.

### 2.5. Sing-box TUIC — нет masquerade-блока

В `singbox_config.py:231-247` (`_build_tuic_inbound`) TUIC-инбаунд генерируется без секции `masquerade`, в отличие от Hysteria2 (`hysteria2_exit_mgr.py:176-180`). При невалидном QUIC-handshake sing-box просто отбрасывает пакет (`singbox_config.py:241` `zero_rtt_handshake: False`). Это не описано как явно признанный пробел, но **контраст с hysteria2** (где masquerade явно прописан) показывает асимметрию защиты.

### 2.6. Slipgate — делегирование внешнему install.sh

> `chimera/modules/slipgate.py:51`
> ```
> • Устанавливает SlipGate одной командой (install.sh от авторов)
> ```

Модуль не генерирует собственные конфиги для DNSTT/NoizDNS/Slipstream/VayDNS — он вызывает внешний `install.sh` (`slipgate.py:130` `_INSTALL_SCRIPT = "https://raw.githubusercontent.com/anonvector/slipgate/main/install.sh"`). Это означает, что **anti-probing поведение под-транспортов не контролируется кодом Chimera** — оно целиком определяется внешним скриптом, который в этом аудите не анализировался. Любые декларации о decoy/fallback для этих под-транспортов требуют отдельного аудита install.sh.

---

## 3. Протоколы без TLS / SNI — decoy не применим тем же способом

Эти протоколы не используют TLS с SNI в привычном смысле, поэтому **TCP+TLS decoy-логика (default_server / ssl_reject_handshake / probe_resistance / fake_site) к ним не применима**. Их anti-probing защита строится на других принципах: либо естественная маскировка под легитимный трафик (WebRTC-звонок, DNS-запрос, STUN-медиа), либо чистый protocol-handshake-failure без decoy. Вынесены в отдельный блок, **не смешиваются со списком TCP+TLS протоколов**.

| # | Протокол | Транспорт | Почему decoy не применим | Что видит пробер вместо decoy | file:line |
|---|---|---|---|---|---|
| A | **hysteria2** | UDP/QUIC | QUIC не использует SNI в TLS-смысле (SNI в QUIC передаётся внутри ClientHello, но семантика другая). Децой через `masquerade: proxy → url` — нативный механизм Hysteria2, не отдельный decoy-слой | Пробер видит **настоящий TLS-сертификат news.ycombinator.com** — Hysteria2 сам проксирует handshake на реальный сайт. Это работает как decoy, но через QUIC-маскарад, не через `default_server` | `hysteria2_exit_mgr.py:176-180` |
| B | **mieru** (mita) | TCP/UDP + mTLS | mTLS = mutual TLS. Клиент обязан предъявить валидный cert, выведенный из password. SNI не используется — нет понятия "чужой SNI" | Пробер получает стандартный `TLS handshake failure` (alert 40) на этапе mutual auth. Decoy не предусмотрен — mita просто обрывает handshake. Поведение опознаётся failregex `TLS handshake failed` (`fail2ban_setup.py:107`) | `mieru.py:7, 11, 38, 1418`; `fail2ban_setup.py:107` |
| C | **wdtt** | UDP/DTLS 1.2 + WRAP | DTLS не имеет SNI. Сам протокол маскируется под медиа-поток звонка через TURN ВКонтакте — трафик выглядит как RTP | Пробер на UDP:56000 получает UDP timeout (RST в UDP не существует). Любой невалидный WRAP-пакет отбрасывается wdtt-server. Защита — естественная маскировка под media-flow на уровне TURN-оператора | `wdtt.py:14, 19-20, 32` |
| D | **turntunnel** (vk-turn-proxy) | UDP/DTLS поверх STUN ChannelData | DTLS+STUN без SNI. Трафик выглядит как медиа-звонок через TURN ВКонтакте | Пробер на UDP:56000 получает UDP timeout. STUN/DTLS-handshake невалидный → отбрасывается. Защита — TURN-операторская | `turntunnel.py:13-18` |
| E | **turnable** | UDP/WebRTC DTLS поверх TURN + TCP loopback Xray | WebRTC DTLS без SNI на VPS-порту; Xray inbound на loopback, не доступен извне | Пробер на UDP:56001 получает UDP timeout. TCP:12767 не доступен извне (loopback) | `turnable.py:14, 19-22, 118-119` |
| F | **olcrtc** | TCP-over-WebRTC (outbound) | Нет listening-порта на VPS — серверная часть подключается к WebRTC-carrier (Jitsi/Яндекс.Телемост) как participant | **Нечего пробовать** — нет открытого порта. Защита — полная: пробер не знает, куда стучаться | `olcrtc.py:4-7, 9-15, 817` |
| G | **slipgate: DNSTT/NoizDNS/Slipstream/VayDNS** | UDP/53 (DNS-протокол) | DNS не имеет TLS-handshake/SNI. Трафик прячется внутри DNS-запросов | Пробер на UDP:53 видит обычный DNS-сервер, отвечающий на реальные DNS-запросы. Децой — естественный: любой DNS-запрос получает валидный DNS-ответ (NXDOMAIN для неизвестных поддоменов) | `slipgate.py:14-19, 28-31` |
| H | **sing-box TUIC** | UDP/QUIC | QUIC без SNI в TLS-смысле. **Никакого masquerade-блока** в конфиге TUIC-inbound (ср. с hysteria2 — `hysteria2_exit_mgr.py:176-180`) | Пробер на UDP:8443 получает UDP timeout. Никакого decoy — sing-box просто отбрасывает невалидный QUIC-пакет. **Это пробел по сравнению с Hysteria2**: оба протокола на QUIC, но только Hysteria2 имеет masquerade | `singbox_config.py:231-247` (сравнить с `hysteria2_exit_mgr.py:176-180`) |

---

## 4. Сводка наблюдений (без рекомендаций — это Фаза 1)

### 4.1. Подтверждённый паттерн `ssl_reject_handshake` / `return 444`

Базовый паттерн anti-probing в Chimera для TCP+TLS протоколов — `ssl_reject_handshake on;` на `default_server` в nginx, с fallback на `return 444` для nginx < 1.19.4 (`nginx_setup.py:743-755`). Этот паттерн применяется:
- ✅ к базовому `vless_state` в классическом REALITY-режиме (`nginx_setup.py:794-800`)
- ✅ к базовому `vless_state` в xHTTP TLS-режиме (`nginx_setup.py:644-650`)
- ✅ к own-site TCP для Telemt (`nginx_setup.py:422-430`)
- ❌ **НЕ применяется** к naiveproxy (использует Caddy + probe_resistance + fake site)
- ❌ **НЕ применяется** к fptn (использует honeypot-прокси на живой контент)
- ❌ **НЕ применяется** к trusttunnel (явное признание: "не имеет SNI-dispatch и не умеет fallback" — `trusttunnel.py:1836`)
- ❌ **НЕ применяется** к subscription (голый `ThreadingHTTPServer` с 404)
- ❌ **НЕ применяется** к admin/user portal (`rest_api.py` — голый HTTP, никакого TLS)
- ❌ **НЕ применяется** к sing-box AnyTLS/TUIC/VLESS-WS-CDN (ShadowTLS — особый случай: проксирует handshake целиком)

### 4.2. Альтернативные модели anti-probing в коде

Chimera реализует **три разные модели** anti-probing для TCP+TLS протоколов:

1. **`ssl_reject_handshake` + `default_server`** — мгновенный RST после ClientHello (vless_state base). Преимущество: не выдаёт ничего. Недостаток: паттерн `TLS-abort after ClientHello` сам по себе опознаваем DPI.

2. **`probe_resistance` + `file_server` с fake site** (naiveproxy) — отдаёт осмысленный decoy-контент ("Welcome / This site is under maintenance"). Преимущество: выглядит как живой (хотя и банальный) сайт. Недостаток: fake-content тривиально отличается от реального сайта домена.

3. **Honeypot-прокси на живой контент** (fptn, ShadowTLS, hysteria2 masquerade) — сервер сам проксирует handshake/TLS-сессию на реальный внешний домен (wikipedia.org / cloudflare.com / news.ycombinator.com). Преимущество: наблюдатель видит **настоящий сертификат** реального сайта и **настоящий контент**. Недостаток: исходящий трафик от VPS к домену-прокси (легко детектируется по traffic analysis).

### 4.3. Пробелы (без предложений по имплементации — Фаза 1)

- **trusttunnel** (`trusttunnel.py:1836`) — явное отсутствие decoy/fallback, порт 8443 TCP+UDP.
- **subscription** (`subscription.py:33-34, 940, 959, 973`) — голый `404 Not Found`, никакой decoy-логики.
- **admin/user portal** (`rest_api.py:1822-1824, 1926-1928`) — голый HTTP без TLS, делегировано внешнему reverse-proxy без собственной генерации конфига.
- **sing-box VLESS-WS-CDN** (`singbox_config.py:275-308`) — origin слушает plain WS; защита только через CDN IP-allowlist, без decoy на самом origin.
- **sing-box TUIC** (`singbox_config.py:231-247`) — без masquerade, контраст с Hysteria2 (`hysteria2_exit_mgr.py:176-180`).
- **slipgate** (`slipgate.py:51, 130`) — anti-probing поведение под-транспортов определяется внешним `install.sh`, не контролируется кодом Chimera.

---

## 5. Используемые отправные точки и расширенные находки

Файлы, просмотренные полностью или частично в этом аудите:

- `chimera/modules/nginx_setup.py` — vless_state base, default_server, ssl_reject_handshake (строки 370-840)
- `chimera/modules/naiveproxy.py` — Caddyfile, probe_resistance, fake site (строки 1-580, 700-750, 1483-1503)
- `chimera/modules/fptn.py` — honeypot-прокси, ALLOWED_SNI_LIST (строки 1-110, 420-530, 630-720, 1390-1410)
- `chimera/modules/trusttunnel.py` — `_guide_overview` строка 1836 (строки 1640-1720, 1815-1875)
- `chimera/modules/mieru.py` — mTLS, server config (строки 1-130, 395-470, 1410-1430)
- `chimera/modules/hysteria2_transport.py` — client-side (строки 1-120); серверная сторона — `hysteria2_exit_mgr.py:160-200` (masquerade!)
- `chimera/modules/hysteria2_cert_mgr.py` — cert management (строки 1-160)
- `chimera/modules/singbox_nginx.py` — SNI-dispatch через stream{} + ssl_preread (строки 1-280, 390-430)
- `chimera/modules/singbox_common.py` — порты ShadowTLS/AnyTLS/TUIC/VLESS-WS-CDN (строки 35-220, 498-540)
- `chimera/modules/singbox_config.py` — генерация inbounds (строки 95-340, 421-680)
- `chimera/modules/wdtt.py` — WRAP/DTLS, port 56000 (строки 1-80, 780-810)
- `chimera/modules/turntunnel.py` — vk-turn-proxy, port 56000 (строки 1-60, 316-340)
- `chimera/modules/turnable.py` — WireTurn, port 56001 (строки 1-120, 460-560)
- `chimera/modules/olcrtc.py` — TCP-over-WebRTC, без listening port (строки 1-30, 425-470, 815-820)
- `chimera/modules/slipgate.py` — meta-протокол, install.sh (строки 1-100, 380-400, 670-830)
- `chimera/modules/subscription.py` — `ThreadingHTTPServer` + 404 (строки 1-60, 160-200, 911-1060, 1450-1480)
- `chimera/modules/rest_api.py` — admin/user portal, голый HTTP (строки 1-75, 1000-1175, 1800-1930)
- `chimera/modules/mtproto.py` — случайно найденный reference на mask_host/own-site fallback (строки 296-360, 805-870, 1830-1880) — **входит в Telemt, не входит в список 17 протоколов этой фазы, упомянут для полноты картины**
- `README.md:75`, `CHANGELOG.md:1412` — дублирующие признания про trusttunnel
