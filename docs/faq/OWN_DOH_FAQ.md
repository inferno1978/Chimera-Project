# FAQ: Собственные DoH-резолверы в сетах b4 (миграция с Cloudflare)

**Контекст:** 6 сентября 2026 все сетевые DNS-редиректы b4 на роутере
переведены с публичного Cloudflare `1.1.1.1` на два собственных
DoH-сервера пользователя (подняты на его VPS, порт 30443).
Причина: РКН начал душить Cloudflare в РФ — резолвер, прописанный
в сетах, стал единой точкой отказа, притом уязвимой ровно там,
где живёт сам обход. Свои серверы эту зависимость убирают.

---

## 1. Что именно настроено

| Сет | DoH (роль) | strict | Эскалация |
|---|---|---|---|
| Youtube-Fat-v1 | `chimeraprodcdn.online:30443` (основной) | true | → Youtube-Heavy-v1 |
| Youtube-Heavy-v1 | `chimeravpn.online:30443` (резерв) | true | — |
| YT-Nocookie-In | `chimeraprodcdn` (основной) | true | → YT-Nocookie-Heavy-v1 |
| YT-Nocookie-Heavy-v1 | `chimeravpn` (резерв) | true | — |
| GitHub-Fat-v1 | `chimeraprodcdn` (основной) | true | → GitHub-Heavy-v1 |
| GitHub-Heavy-v1 | `chimeravpn` (резерв) | true | — |
| XHamster-Smooth-v5 | `chimeraprodcdn` (основной) | true | → XHamster-Heavy-v1 |
| XHamster-Heavy-v1 | `chimeravpn` (резерв) | true | — |
| XVideos-v1 | `chimeraprodcdn` (основной) | true | → XVideos-Heavy-v1 |
| XVideos-Heavy-v1 | `chimeravpn` (резерв) | true | — |
| Meta-Universal-v1 | `chimeraprodcdn` (основной) | true | → Meta-Heavy-v1 |
| Meta-Heavy-v1 | `chimeravpn` (резерв) | true | — |
| NNM-Fat-v1 | `chimeraprodcdn` (основной) | true | → NNM-Heavy-v1 |
| NNM-Heavy-v1 | `chimeravpn` (резерв) | true | — |

Все 7 DNS-сетов с парами (первые 3 пары — YouTube/GitHub/NNM —
были с самого начала, 4 доклеены 6 сентября вечером). Не тронуты
(DNS-редирект изначально выключен, наружу из них ничего не ходит):
`Telegram-WS-Bridge`, `YT-Wide-Legacy`, `speedtest`.

Серверы: `chimeraprodcdn.online` (138.124.255.238, серт Let's Encrypt
до 30.10.2026) — основной; `chimeravpn.online` (91.224.87.154, серт
до 27.11.2026) — резерв. Оба: RFC 8484 (POST с фолбэком на GET),
TLS 1.3, ~1 с отклик из РФ.

## 2. Как работает primary/backup (это НЕ список в одном поле)

В b4 поле `sets[X].dns.doh_url` — одиночная строка; списка серверов
нет. Резерв делается эскалацией, как для трафика:

- 2 плохих DNS-ответа подряд на домен (SERVFAIL/NXDOMAIN/пустой A)
  или смерть источника без фолбэка → `escalate.dns_threshold` (2)
  → домен уезжает в Heavy-сет целиком: и DNS, и трафик.
- DNS-путь консультирует таблицу эскалаций напрямую
  (`nfq/dns.go`, `escalatedSetFor`) — резервный DoH включается
  без повторных ударов в мёртвый основной.
- Состояние живёт `escalate.ttl_sec` (3600): через час само
  вернётся на основной. Хороший ответ сбрасывает счётчик.

Дизайн Heavy-сета (единообразный для всех 7 пар): **targets пустые** —
сет матчится только через таблицу эскалаций (`escalatedSetFor`
подменяет сет для домена: и DNS, и трафик) и dns-hint от собственных
ответов. Напрямую он ничего не перехватывает, а если Fat выключить —
трафик просто перестанет матчиться (fail-closed, в духе strict).
Профиль Heavy — другая ось обхода, чтобы эскалация меняла не только
DNS, но и способ доставки: Heavy собраны через `duplicate(Fat)` +
доводка (frag combo→tcp, faking →pastseq, desync ack/2, sni_mutation
full, ip_block_detect cache/syn — набор зависит от пары).

Найденный по ходу баг: у `YT-Nocookie-In` escalate-поля были нулями
(rst/ttl/stall/dns_threshold) — при пустом `escalate.to` это молчало,
но после привязки пары проставлены явно (rst 3/30с, ttl 3600с,
stall 3/3000мс, dns_threshold 2), как у остальных пар.

## 3. strict=true: «наружу — ничего»

Семантика из `src/nfq/dnscache.go` (`dnsRedirectFallback`):
при `strict=false` после 3 фейлов источника b4 30 секунд держит
кулдаун и **фолбэчится** — сначала в кэш, потом к исходному
DNS-серверу клиента (plain 53, наружу). При `strict=true` фолбэк
отключён целиком: единственный источник — прописанный DoH,
иначе SERVFAIL. Эскалацию strict НЕ блокирует — она вызывается
в обеих ветках (`nfq/dns.go:542/558`), так что фейловер на
резерв работает.

**Осознанный trade-off:** упадут оба своих сервера — DNS матченных
доменов встанет (fail-closed). Это цена требования «не уходить
наружу». Размягчить точечно: `strict=false` на конкретном сете
вернёт кэш-фолбэк.

## 4. Петли иsame-VPS: почему это безопасно

- Собственные исходящие b4 помечены (SelfDialMark 0x40000 +
  injected mark) и исключены из своих же перехватов — b4, ходящий
  на DoH, живущий на той же машине (роутер/двух VPS-инстансах),
  себя не перехватывает.
- Хостнейм DoH резолвится системным резолвером — на роутере это
  dnscrypt-стек (тоже своё), не петля.
- Серт обязателен валидный: в DoH-клиенте b4 нет
  `InsecureSkipVerify` — Let's Encrypt на hostname подходит,
  самоподпис — нет (без своего CA в trust store).

## 5. Проверка после миграции (живые улики)

- `recent_connections contains=dns-doh`: до свапа
  `dns-doh->1.1.1.1`, после — `dns-doh->chimeraprodcdn.online:30443`
  (nnmclub.to, github.com, youtube.com; включая запросы самого
  роутера — output-hook перехватывает и dnsmasq-плечо).
- `recent_connections contains=servfail` — пусто (0 DNS-ошибок).
- Watchdog 6/6 healthy (www.youtube.com 89 КБ/с, nnmclub.to
  72 КБ/с, github.com 47 КБ/с).
- `b4_test_domain_now` nnmclub.to: baseline TLS_DROP (блок на месте),
  through_b4 35 КБ/с — сет пережил миграцию.

Снимок конфигурации: `vendor/b4/set-artifacts/*.json` (dns-блоки
обновлены, `_meta` описывает миграцию).

## 6. Урок канала: почему MCP отваливался полтора часа

Симптом: 9 точек мира (check-host) — TCP timeout на 7000, при этом
роутер онлайн, b4 жив (uptime, ps). Причина оказалась двухслойной:

1. **Правило INPUT жило только в runtime.** `iptables -I INPUT
   -p tcp --dport 7000 -s 47.57.0.0/16` из SSH-сессии не переживает
   пересборку firewall (WAN-флап, рестарт сетевых служб) — на ASUS
   с Merlin ruleset пересобирается без ребута. Диагноз: `iptables -C
   ... && echo ALIVE || echo GONE`.
2. **Egress песочницы ротируется.** 47.57.0.0/16 → 8.212.0.0/16 за
   сутки — source-белое правило молча перестало матчить.

Лечение (персистентно, Merlin):
`/jffs/scripts/firewall-start` — блок `iptables -C || -I` для обеих
подсетей (append в конец, скрипт выполняется на каждом старте
firewall). Правило узкое: INPUT (трафик к роутеру), tcp/7000,
две /16. На стоке — cron-дозор через Entware.

Глубина защиты: даже мимо правила — b4 сам защищён (MCP требует
Bearer, веб-морда — логин/пароль).

## 7. Осталось сделать (по желанию)

- ~~Одиночным сетам собрать Heavy-пары~~ — готово (06.09, вечером):
  4 пары XHamster/XVideos/Meta/YT-Nocookie, живые проверки в
  `set-artifacts/*.json` (`_meta.live_check`).
- Нюанс `www.youtube-nocookie.com`: падает в обе стороны (и через
  b4, и мимо) — блок адресного уровня, DNS ни при чём (prodcdn/vpn/CF
  отдают здоровые Google-IP). Пара собрана; стилл-эскалация при 3
  фейлах подряд попробует Heavy-ось.
- На двух VPS, где b4 крутится рядом с DoH: прописать по той же
  схеме с приоритетом локального сервера (co-located — суб-мс) и
  кросс-VPS резервом.
