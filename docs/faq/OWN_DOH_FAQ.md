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
| Youtube-Fat-v1 | `cdn.example:30443` (основной) | true | → Youtube-Heavy-v1 |
| Youtube-Heavy-v1 | `panel.example:30443` (резерв) | true | — |
| YT-Nocookie-In | `cdn-vps` (основной) | true | → YT-Nocookie-Heavy-v1 |
| YT-Nocookie-Heavy-v1 | `vpn-node` (резерв) | true | — |
| GitHub-Fat-v1 | `cdn-vps` (основной) | true | → GitHub-Heavy-v1 |
| GitHub-Heavy-v1 | `vpn-node` (резерв) | true | — |
| XHamster-Smooth-v5 | `cdn-vps` (основной) | true | → XHamster-Heavy-v1 |
| XHamster-Heavy-v1 | `vpn-node` (резерв) | true | — |
| XVideos-v1 | `cdn-vps` (основной) | true | → XVideos-Heavy-v1 |
| XVideos-Heavy-v1 | `vpn-node` (резерв) | true | — |
| Meta-Universal-v1 | `cdn-vps` (основной) | true | → Meta-Heavy-v1 |
| Meta-Heavy-v1 | `vpn-node` (резерв) | true | — |
| NNM-Fat-v1 | `cdn-vps` (основной) | true | → NNM-Heavy-v1 |
| NNM-Heavy-v1 | `vpn-node` (резерв) | true | — |

Все 7 DNS-сетов с парами (первые 3 пары — YouTube/GitHub/NNM —
были с самого начала, 4 доклеены 6 сентября вечером). Не тронуты
(DNS-редирект изначально выключен, наружу из них ничего не ходит):
`Telegram-WS-Bridge`, `YT-Wide-Legacy`, `speedtest`.

Серверы: `cdn.example` (203.0.113.103, серт Let's Encrypt
до 30.10.2026) — основной; `panel.example` (203.0.113.102, серт
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
  `dns-doh->1.1.1.1`, после — `dns-doh->cdn.example:30443`
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
  кросс-VPS резервом. Этап 1 сделан 06.09 на ОБОИХ инстансах —
  cdn-vps и vpn-node (Heavy-схема с эскалацией, DNS не
  тронут — см. §8); остался сам этап DNS (по команде юзера).

## 8. VPS-инстансы: Heavy-схема без DNS (этап 1 — cdn-vps и vpn-node)

На VPS `cdn.example` b4 (v1.81.0, доступ через MCP с
Bearer) маршрутит собственный исходящий трафик сетами — и его
egress тоже под цензурой (baseline до youtube.com с VPS =
TLS_DROP). 06.09 на нём выстроена та же схема «Fat + Heavy +
эскалация», что на роутере, — по явному указанию «DNS пока не
прописываем»: dns-блоки не тронуты ни у одного сета (у
YouTube/Meta остался Cloudflare 1.1.1.1, у XHamster — локальный
127.0.0.1, у YT-Wide — выключен).

**Сеты (8, было 5):** пара Youtube-Fat/Heavy существовала —
проверена как есть; новые: Meta-Universal→Meta-Heavy,
XHamster-Smooth→XHamster-Heavy, YT-Wide-Legacy→YT-Wide-Heavy.
Рецепт роутерный: duplicate(Fat) → вычистка targets
(эскалация-only) → heavy-профиль с другой осью десинка (desync
ack/2, pastseq, sni_mutation full; Meta/YT-Wide ещё frag→tcp) →
on Fat escalate.to с порогами rst 3/30с / ttl 3600с / stall
3/3000мс / dns 2.

**Почему эскалация работает без DNS:** триггеры stall / forged
RST / dead IP — чисто трафиковые (handler.go:599, inc.go:61,
ipblock.go:101); DNS-триггер (dns.go:181) включится сам, когда
пропишем DoH. Пороги даже при нулях добираются дефолтами
(Resolved*-геттеры).

**Живая проверка (06.09):** watchdog 5/5 healthy, 0 фейлов —
www.youtube.com 117.8 КБ/с, www.facebook.com 33.1 (Meta),
xhamster.com 34.5 (Fat). Артефакты:
`set-artifacts/vps-prodcdn/*.json`.

**Пост-мортем (08.09): старая «улика эскалации» была миной.**
Ранее здесь стояла «главная улика»: CDN-стриминг
`fi.fleet-b.example` через XHamster-Heavy (40/40) якобы
доказывал работу эскалации. Ложь: матчи были глобальным
перехватом порта. duplicate(XHamster-Smooth) наследовал
tcp.dport_filter='443', «вычистка targets» удаляла только
sni/ip/geosite/geoip — порт оставался. Сет с dport_filter и
ПУСТЫМИ targets в b4 = global port-only (sni.MatchTCPPort),
ловит ВЕСЬ TCP/443. На prodcdn 100/100 исходящих коннектов
сервера (Telegram-DC 149.154.x, fleet, DoH) получали
heavy-десинк; на vpn-node — 35/100 с retry-loop в
1.1.1.1:443 каждые 200-400 мс (ломающиеся хендшейки).
Фикс 08.09: dport_filter '' на роутере и обеих VPS (live);
после него SNI-less матчи исчезли в ноль => «IP-хинтов»
не существовало. Выводы: (а) у эскалация-only сета dport_filter
обязан быть пуст — проверка «targets пустые» без проверки порта
недостаточна (verify 53/53 мину пропустил); (б) матч без SNI —
в первую очередь подозрение на port-only перехват, эскалационный
IP-хинт — последняя гипотеза, не первая.

**vpn-node (вторая нода, 06.09 поздним вечером):** юзер принёс
MCP-эндпоинт — сделано «то же самое». Было 5 сетов (пара только у
YouTube); собраны Meta-Heavy / XHamster-Heavy / YT-Wide-Heavy,
эскалационные пороги на всех Fat, верификация 53/53, DNS не тронут
(у YouTube/Meta — Cloudflare 1.1.1.1, у XHamster — локальный
127.0.0.1, у YT-Wide — выкл). Watchdog 5/5 healthy (добавлены
www.facebook.com и xhamster.com): www.youtube.com 136-141 КБ/с,
xhamster.com 24.8 КБ/с. Эскалация xhamster.com (адрес, где
Fat-ось ловит RST): коннекты переброшены XHamster-Smooth-v5 →
XHamster-Heavy-v1, 21/100 свежих коннектов — эта часть была
настоящей эскалацией (SNI матчит Smooth). SNI-less DNS-путь b4
к 1.1.1.1:443, ошибочно записанный тогда как «атрибуция
эскалированного флоу», был той же port-only миной (доказано
08.09: после снятия dport_filter — retry-loop исчез, 0/100).
Эпизод www.facebook.com «degraded» (TCP RST) ретроспективно
заподозрен в работе мины, а не в транзиенте egress.
Артефакты: `set-artifacts/vps-vpn/*.json`.

Этап 2 (по команде): прописать DoH по co-located схеме
(prodcdn-сеты → свой DoH первично + vpn-node-резерв; vpn-сеты →
свой + cdn-vps-резерв) — на обеих нодах этап 1 завершён.
