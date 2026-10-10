# Entry-нода за ингресс-фильтром: GRE-playbook (возрождение ноды)

**Дата:** 2026-10-10
**Статус:** конфигурация живая на ноде; документ зафиксирован post-factum, чтобы опыт не потерялся

---

## Контекст и TL;DR

Entry-нода стоит за апстрим-ингресс-фильтром хостера, который дропает **все входящие TCP-сегменты с payload** и **весь входящий UDP**, но **не трогает ICMP и GRE (IP proto 47)**. Классические инбаунды (VLESS/TLS напрямую, OpenVPN, WireGuard, anything TCP/UDP) на такой ноде невозможны в принципе: payload до приложения не доходит, UDP мёртв. Это доказано на уровне NIC (tcpdump) и 11-конфигурационной матрицей серверных техник — фильтр стоит апстримом, до машины, серверными трюками не обходится.

Решение: нода остаётся entry, но клиенты добираются до неё **через транспорты, прозрачные для фильтра**:

```
[клиент LAN] ──GRE(proto 47)──> [entry-нода: xray VLESS REALITY :443] ──VLESS, прямой TCP──> [hop-бокс] ──VLESS-в-VLESS──> [exit-1..5] ──> интернет
```

- **Основной канал:** GRE-туннель нода ↔ домашний роутер (L3, в ядре, без userspace). Замер E2E: RTT ~10 мс, ~290 Мбит/с down / ~840 Мбит/с up через полный каскад.
- **Запасной канал:** ICMP-туннель (pingtunnel). Работает в простое, но путь домашнего ISP полисит ICMP под нагрузкой (поток умирает через ~1 с после старта браузера, потолок ~7 Мбит/с). Годится только как аварийный.

Плейбук ниже содержит: модель фильтра (что и как проверялось), полную итоговую конфигурацию ноды, настройку GRE со стороны ноды и роутера (Asus/Merlin), разбор ICMP-варианта, **резервные транспорты на случай, если GRE задушат**, и операционку (доступ/мониторинг/разбор).

Все адреса, ключи и домены в тексте — плейсхолдеры: `<NODE_IP>`, `<EXIT_A_IP>`, `<HOME_IP>`, `<SNI_DOMAIN>`, `<UUID>`, `<REALITY_PUBKEY>`, `<SHORT_ID>`, `<ICMP_KEY>`. Внутренние подсети туннелей — примерные (`10.0.0.0/30`, `10.0.0.4/30`), при восстановлении подставить свои.

---

## 1. Модель ингресс-фильтра (что и как доказано)

Метод: tcpdump на NIC ноды + генераторы трафика с зарубежного хоста и с RU-хоста + scapy raw-сокеты (корректные чексуммы) + серверная матрица техник.

### Входящее к ноде

| Транспорт | Результат |
|---|---|
| TCP SYN/ACK (хендшейк) | ✅ проходит |
| TCP payload-сегменты | ❌ дроп, 0 из ~60 попыток за все тесты |
| TCP payload IP-фрагментами | ⚠️ только ПЕРВЫЙ бёрст соединения доходит (fragsize 24–48); второй и далее — дроп |
| UDP (любые порты, 2 источника) | ❌ полный дроп, 0/14 датаграмм |
| ICMP (payload 1408/1828 байт, фрагментированные) | ✅ проходит, обратка чистая |
| GRE (proto 47) | ✅ проходит, двунаправленно, sustained (100 пингов 0% loss, полный TLS/VLESS E2E внутри) |

### Исходящее от ноды

| Транспорт | Результат |
|---|---|
| TCP (в т.ч. за рубеж) | ✅ чист |
| UDP за рубеж | ❌ мёртв (на трансграничном участке) |
| ICMP / GRE | ✅ чисты в обе стороны |

### Серверная матрица (11 конфигураций) — вывод

Прогнаны: базлайн, mss_clamp, syn_fake, window zero/oscillate, duplicate, desync full, egress-фрагментация, incoming fake/desync (targets=свой IP), RST-защита, всё-вместе. **Входящих payload-пакетов за всю матрицу: 0.** Фильтр апстримный, до машины — серверные техники бессильны в принципе. Единственный рабочий обход — смена транспорта: GRE/ICMP.

**Практическое следствие:** любой протокол, который выглядит как TCP-сессия или UDP-флоу к ноде, мёртв на ингрессе. Живы только «глухие» для фильтра IP-протоколы (см. раздел 5).

---

## 2. Итоговая конфигурация ноды

### 2.1 Состав

**Data plane** (пользовательский трафик):

| Компонент | Назначение |
|---|---|
| xray (Xray 26.9.30): VLESS TCP REALITY `:443` (слушает `*:443`) | инбаунд для клиентов (приходят через greHOME) + исходящий каскад-балансер на 5 экзитов roundRobin — архитектура в 2.6 |
| `grehome.service` | GRE к домашнему роутеру: `10.0.0.5/30` ↔ `10.0.0.6/30` — единственный путь клиентов к ноде (proto 47 фильтром пропускается) |
| hop-бокс (= exit-A, GRE-пир grepl) | первая ступень каскада: VLESS REALITY; соединение инициирует сама нода прямым TCP — обратка своих соединений фильтром пропускается |

**Management plane** (доступ/резерв, юзерским трафиком не нагружаются):

| Компонент | Назначение |
|---|---|
| `grepl.service` | GRE к exit-A: `10.0.0.1/30` ↔ `10.0.0.2/30` — ТОЛЬКО SSH/мониторинг; пользовательский трафик через него НЕ идёт |
| `grepl-keepalive.service` | ping `10.0.0.2` каждые 55 с (держит conntrack живым, см. урок 2.4) |
| `pingtunnel.service` | ICMP-сервер (TCP-over-ICMP → локальный xray), аварийный канал |
| b4 (v1.85.1) | установлен, **конфиг без сетов** (безопасно), web UI на `127.0.0.1:7000` |

### 2.2 GRE к exit-A (`/etc/systemd/system/grepl.service`)

Реализация — юнит с инлайн-командами (идемпотентный `add || change`):

```ini
[Unit]
Description=GRE tunnel to exit-A (grepl)
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip tunnel add grepl mode gre local <NODE_IP> remote <EXIT_A_IP> ttl 64 2>/dev/null || ip tunnel change grepl mode gre local <NODE_IP> remote <EXIT_A_IP> ttl 64; ip addr add 10.0.0.1/30 dev grepl 2>/dev/null; ip link set grepl up'
ExecStop=/bin/sh -c 'ip tunnel del grepl 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
```

Keepalive — отдельный сервис (systemd сам держит его живым, это проще цикла в скрипте):

```ini
[Unit]
Description=grepl keepalive (conntrack)
After=grepl.service

[Service]
Type=simple
ExecStart=/bin/ping -i 55 -q 10.0.0.2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 2.3 GRE к домашнему роутеру

Файл удалённого адреса: `/etc/gre-home-remote` (одна строка — публичный IP роутера; при статике не меняется).

`/usr/local/sbin/gre-home-up.sh`:

```bash
#!/bin/bash
REMOTE=$(head -1 /etc/gre-home-remote 2>/dev/null)
[ -z "$REMOTE" ] && { echo "no /etc/gre-home-remote"; exit 1; }
if ip tunnel show greHOME 2>/dev/null | grep -q greHOME; then
  exit 0
fi
modprobe ip_gre
ip tunnel add greHOME mode gre local <NODE_IP> remote "$REMOTE" ttl 64
ip addr add 10.0.0.5/30 dev greHOME
ip link set greHOME up
```

`/etc/systemd/system/grehome.service` — такой же oneshot/RemainAfterExit, как grepl выше, с ExecStart/ExecStop на up/down-скрипты. Enabled.

### 2.4 Файрвол (UFW) — три урока

1. **`ufw allow proto 47` — невалидный синтаксис**, ufw протокол GRE не умеет («Unsupported protocol»). Правильное решение — постоянное правило в `/etc/ufw/before.rules` (строка в секции `*filter`, до COMMIT):
   ```
   -A ufw-before-input -p 47 -j ACCEPT
   ```
   Ядро само принимает пакеты GRE только от remote-адреса, прописанного в туннеле, так что правило безопасно.
2. **Conntrack-урок:** без явного allow GRE живёт на `conntrack ESTABLISHED` от исходящего трафика ноды (таймаут generic-протокола 600 с). E2E проходит по живому состоянию, а после ~10 минут простоя туннель «умирает» (пинг с той стороны 100% loss при живых сервисах). Лечится именно before.rules + keepalive. **В обоих направлениях.**
3. **Per-interface allow для SSH-резерва:** `ufw allow in on grepl` (и `on greHOME`) — SSH до ноды остаётся доступен через туннель, когда прямой путь лежит.

Итоговые правила UFW: `22,80,443/tcp` + `allow in on grepl` + `allow in on greHOME` + proto 47 в before.rules.

### 2.5 Урок про DPI-инструментарий на ноде

**Не создавать в b4/NFQUEUE-инструментах сетов, которые матчат IP exit-ноды или исходящий к туннелям трафик** — NFQUEUE-правила экспериментальных сетов эмпирически ломали GRE. Если b4 нужен — конфиг без сетов.

### 2.6 Data plane: VLESS REALITY + каскад (relay-схема)

Пользовательский трафик **не ходит через GRE к exit-нодам** — grepl чисто менеджментский. Реальный путь:

```
[клиент LAN]
   │ vless://... на 10.0.0.5:443 (внутренний адрес GRE)
   ▼ GRE (proto 47)
[entry-нода: xray VLESS REALITY :443]  ← терминирует клиентский VLESS
   │ xray outbound "hop": ПРЯМОЙ TCP (соединение инициирует сама нода)
   ▼
[hop-бокс: VLESS REALITY]  ← 5-й экзит = сам hop (свой freedom-исход)
   │ TCP к экзитам набирается ВНУТРИ туннеля до hop (dialerProxy → VLESS-в-VLESS)
   ├──> [exit-1: VLESS REALITY] ──> internet
   ├──> [exit-2] / [exit-3] / [exit-4]
   └─ balancer roundRobin по 5 экзитам (chain-exit-1..5)
```

**Почему это работает за фильтром.** Фильтр режет payload входящих ИЗВНЕ TCP-соединений — нода не может принимать коннекты снаружи. Но **обратный трафик соединений, инициированных самой нодой, фильтр пропускает на полной скорости** (доказано замером: 841 Мбит/с входящего по прямому TCP на нода-инициированном соединении). Поэтому: клиенты добираются до ноды через GRE (proto 47 не фильтруется), а нода сама набирает hop по прямому TCP. Тройная инкапсуляция пользовательских данных: VLESS(клиент→нода) → VLESS(нода→hop) → VLESS(нода→экзит, внутри хопа).

**Почему dialerProxy, а не маршрутизация на hop-боксе:** все креды экзитов (UUID/REALITY-ключи на каждый экзит) живут в одном конфиге ноды — hop-бокс ничего не знает об экзитах и не требует настройки при их смене; балансировка и ротация тоже управляются из одной точки.

Инбаунд (скелет, все секреты — плейсхолдеры):

```json
{
  "tag": "inbound-vless", "port": 443, "listen": "::", "protocol": "vless",
  "settings": { "clients": [ { "id": "<UUID>", "email": "<USER_EMAIL>", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
  "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false },
  "streamSettings": {
    "network": "tcp",
    "sockopt": { "tcpKeepAliveInterval": 15, "tcpKeepAliveIdle": 60, "tcpUserTimeout": 30000, "tcpCongestion": "bbr" },
    "security": "reality",
    "realitySettings": {
      "dest": "/dev/shm/<SOCKET>.socket", "xver": 1, "spiderX": "<SPIDER_PATH>",
      "serverNames": ["<SNI>"], "privateKey": "<PRIVATE_KEY>", "shortIds": ["<SHORT_ID>"]
    }
  }
}
```

- `dest` — unix-сокет nginx (в `/dev/shm`): не-REALITY запросы уходят в nginx-заглушку (HTTP 400), для сканеров порт выглядит обычным веб-сервером. `xver 1` — PROXY-протокол v1.
- `sniffing` с `destOverride http/tls/quic` — чтобы маршрутизация видела домены (metadataOnly: false).

Каскад (outbounds, скелет):

```json
{ "tag": "hop", "protocol": "vless",
  "settings": { "vnext": [ { "address": "<HOP_IP>", "port": 443,
    "users": [ { "id": "<HOP_UUID>", "encryption": "none", "flow": "xtls-rprx-vision" } ] } ] },
  "streamSettings": { "network": "tcp", "security": "reality",
    "sockopt": { "tcpCongestion": "bbr", "...": "keepalive как в инбаунде" },
    "realitySettings": { "fingerprint": "firefox", "serverName": "<SNI_HOP>",
      "publicKey": "<HOP_PUBKEY>", "shortId": "<HOP_SID>", "spiderX": "/" } } }

{ "tag": "chain-exit-N", "protocol": "vless",
  "settings": { "vnext": [ { "address": "<EXIT_N_IP>", "port": 443,
    "users": [ { "id": "<EXIT_N_UUID>", "flow": "xtls-rprx-vision" } ] } ] },
  "streamSettings": { "network": "tcp", "security": "reality",
    "sockopt": { "dialerProxy": "hop", "tcpCongestion": "bbr" },   // ← релейная схема
    "realitySettings": { "fingerprint": "firefox", "serverName": "<SNI_EXIT_N>",
      "publicKey": "<EXIT_N_PUBKEY>", "shortId": "<EXIT_N_SID>", "spiderX": "/" } } }

{ "tag": "chain-exit-5" }            // 5-й экзит = сам hop-бокс: БЕЗ dialerProxy,
                                     // прямое VLESS на него (UUID совпадает с hop)
{ "tag": "BLOCK", "protocol": "blackhole" }
{ "tag": "direct", "protocol": "freedom" }
{ "tag": "dns-out", "protocol": "dns" }
```

Routing + balancer (скелет, порядок правил важен):

```json
"routing": { "domainStrategy": "IPIfNonMatch", "rules": [
  { "inboundTag": ["stats-api"], "outboundTag": "stats-api" },
  { "ip": ["127.0.0.1/8", "::1/128"], "outboundTag": "direct" },
  { "protocol": ["bittorrent"], "outboundTag": "BLOCK" },
  { "port": "53", "network": "tcp,udp", "outboundTag": "dns-out" },
  { "port": "443", "network": "udp", "outboundTag": "BLOCK" },   // QUIC → в BLOCK
  { "network": "udp", "outboundTag": "BLOCK" },                  // весь остальной UDP
  { "network": "tcp", "balancerTag": "chain-balancer" } ],
  "balancers": [ { "tag": "chain-balancer",
    "selector": ["chain-exit-1", "chain-exit-2", "chain-exit-3", "chain-exit-4", "chain-exit-5"],
    "strategy": { "type": "roundRobin" } } ] }
```

**Почему весь UDP заблокирован:** исходящий международный UDP ноды мёртв (раздел 1). Если бы xray честно пытался проксировать UDP/QUIC наружу — зависания. BLOCK по UDP заставляет браузеры откатываться на TCP (TCP → balancer), DNS клиентов заворачивается в `dns-out` (резолверы: доступный из страны ноды + публичный запасной, `queryStrategy: UseIPv4`, hosts-пиннинг резолверов).

Прочее:
- Статистика per-user (uplink/downlink) включена в `policy`; API статистики — dokodemo-door на `127.0.0.1:10085` (StatsService + HandlerService).
- Юнит systemd: `User=xray`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE`, `LimitNOFILE=1048576`, `Nice=-10`, `Restart=on-failure` c `RestartPreventExitStatus=23` (23 = невалидный конфиг — не рестартовать бесконечно).
- Файрвол-минимум для этой схемы: `443/tcp` в UFW (клиенты приносят трафик через greHOME — он уже разрешён per-interface) + proto 47 в before.rules.

---

## 3. GRE нода ↔ домашний роутер (Asus Merlin)

### 3.1 Предусловия (проверить ДО настройки)

1. **Белый публичный IP у роутера** (не CGNAT). Проверка: WAN IP в веб-морде == IP, под которым тебя видит интернет (2ip.io с любого устройства LAN). Если WAN начинается с `100.64.`/`10.`/`172.16-31.` — CGNAT, GRE невозможен, сначала получить белый IP у ISP.
2. **Модуль ядра `ip_gre`** в прошивке. Проверка по SSH на роутере:
   ```sh
   uname -r
   modprobe ip_gre
   WANIP=$(nvram get wan0_ipaddr)
   ip tunnel add greTEST mode gre local $WANIP remote <NODE_IP> ttl 64
   ip tunnel del greTEST
   ```
   Всё молча прошло — модуль есть. Проверено на GT-AX11000 / Merlin, ядро 4.1.51 — работает из коробки.
3. **Статика или DDNS.** При статическом IP роутера ничего не нужно. При динамическом — включить DDNS в Merlin (WAN → DDNS) и на ноде пересоздавать туннель по имени (cron-сторож: пинг упал → резолвим DDNS → `ip tunnel change greHOME remote <new>`).

### 3.2 Сторона ноды

Однократно (адрес роутера в `/etc/gre-home-remote`), скрипты и systemd из раздела 2.3, `systemctl enable --now grehome`, плюс `ufw allow in on greHOME`.

### 3.3 Сторона роутера — разовый запуск

```sh
WANIP=$(nvram get wan0_ipaddr)
modprobe ip_gre
ip tunnel del greHOME 2>/dev/null
ip tunnel add greHOME mode gre local $WANIP remote <NODE_IP> ttl 64
ip addr add 10.0.0.6/30 dev greHOME
ip link set greHOME up mtu 1476
ip route replace 10.0.0.4/30 dev greHOME
iptables -t nat -D POSTROUTING -o greHOME -j MASQUERADE 2>/dev/null
iptables -t nat -A POSTROUTING -o greHOME -j MASQUERADE
iptables -D FORWARD -i br0 -o greHOME -j ACCEPT 2>/dev/null
iptables -I FORWARD -i br0 -o greHOME -j ACCEPT
iptables -D FORWARD -i greHOME -o br0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
iptables -I FORWARD -i greHOME -o br0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t mangle -D FORWARD -o greHOME -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
iptables -t mangle -A FORWARD -o greHOME -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ping -c 5 10.0.0.5   # ← нода должна ответить, 0% loss
```

### 3.4 Автозапуск на роутере (Merlin, jffs)

`/jffs/scripts/gre-home.sh` — тот же блок, что в 3.3, обёрнутый в `#!/bin/sh` + `logger -t gre-home "tunnel up via $WANIP"`. Подключение:

```sh
if [ -f /jffs/scripts/wan-start ]; then
  grep -q gre-home /jffs/scripts/wan-start || echo '/jffs/scripts/gre-home.sh' >> /jffs/scripts/wan-start
else
  printf '#!/bin/sh\n/jffs/scripts/gre-home.sh\n' > /jffs/scripts/wan-start
fi
chmod +x /jffs/scripts/wan-start /jffs/scripts/gre-home.sh
```

Скрипт идемпотентный (сначала `del`, затем `add`), безопасен при повторных запусках. Вызывается на каждое поднятие WAN.

### 3.5 Нюансы, пойманные в бою

- **MTU:** дефолт GRE — 1476. Если у провайдера PPPoE (WAN MTU 1492) — ставить 1468, иначе большие пакеты подвисают. Обычный IPoE/DHCP — 1476 ок.
- **MSS:** без `TCPMSS --clamp-mss-to-pmtu` сайты с большими ответами могут «виснуть» на handshake.
- **Встречный пинг нода→роутер** режется INPUT-политикой Merlin (greHOME считается внешним интерфейсом). На транзит LAN это НЕ влияет (идёт через FORWARD), но для диагностики полезно добавить: `iptables -I INPUT -i greHOME -j ACCEPT`.
- **Клиентский профиль:** vless-ссылка на внутренний адрес ноды `10.0.0.5:443` (шаблон):
  ```
  vless://<UUID>@10.0.0.5:443?type=tcp&security=reality&pbk=<REALITY_PUBKEY>&fp=firefox&sni=<SNI_DOMAIN>&sid=<SHORT_ID>&flow=xtls-rprx-vision#entry-GRE
  ```
  Работает для всей LAN без клиентских туннелей: роутер сам заворачивает 10.0.0.4/30 в GRE.

### 3.6 Замеры (для калибровки ожиданий)

| Метрика | Значение |
|---|---|
| RTT дом ↔ нода (GRE) | ~10 мс |
| E2E через каскад, download | ~290–315 Мбит/с |
| E2E через каскад, upload | ~790–840 Мбит/с |
| Нода → hop, прямой TCP, 4 потока (нога отдачи каскада) | ~3.65 Гбит/с |
| Hop → нода, прямой TCP @800M (нога скачивания каскада) | 841 Мбит/с |
| GRE hop ↔ нода (только менеджмент-плоскость) | ingress 595 @600M (@800M убивается); egress — жёсткий шейп ~335 |
| Для сравнения: ICMP-вариант | ~7 Мбит/с, умирает под нагрузкой |

Разложение по ногам и вердикт по асимметрии — в 3.7. Важно: GRE к hop-боксу в пользовательском пути НЕ участвует (менеджмент-плоскость, см. 2.1/2.6); ноги каскада — прямые TCP-соединения, инициированные нодой.

### 3.7 Асимметрия down/up (~300 вниз / ~800–900 вверх): вердикт по замерам 2026-10-10

Чтобы найти, где именно сидит потолок скачивания, ноги каскада промерены отдельно (iperf3, сервер на hop-боксе, клиент на ноде, 8–12 с на тест):

| Нога | Измерено |
|---|---|
| нода → hop, прямой TCP, 4 потока (нога отдачи каскада) | ~3.65 Гбит/с |
| hop → нода, прямой TCP @800M (нога скачивания каскада) | 841 Мбит/с принято |
| hop → нода, GRE @600M / @800M (менеджмент, не юзерский путь) | 595 Мбит/с / поток убивается |
| нода → hop, GRE (менеджмент) | жёсткий шейп ~335 Мбит/с (0 ретрансмиссий) |
| E2E через полный каскад | download ~290–315 / upload ~790–840 Мбит/с |

**Вывод: нода и её транзит — НЕ bottleneck.** Обе ноги каскада держат 800+ Мбит/с. Единственный незамеренный сегмент — домашняя сторона (greHOME-нога + последний милли домашнего ISP), и числа сходятся именно на ней: upload ~790–840 — потолок отдачи домашнего канала; download ~290–315 — потолок его скачивания (тариф либо ингресс-полисер ISP — прецедент полисинга у этого ISP уже есть, см. 4.2). Косвенное подтверждение: два разных экзита каскада (разные страны, разные серверы спидтеста) дали одинаковые ~290/315 — общее у них только дом. Роутер тоже не при чём: отдача 790+ проходит через тот же CPU-путь роутера (GRE encap/forward), значит и скачивание он бы не порезал.

**Как правильно сделать контрольный тест «без прокси»** (на собственных граблях): на скриншоте такого теста смотреть IP и сервер — если IP иностранный и сервер за рубежом, прокси был включён и тест ничего не контролирует. Правильно: полностью остановить прокси-клиент → проверить свой IP на 2ip.io (должен быть домашний) → speedtest. Ожидание по нашим замерам: download тоже ~300 — тогда перекос целиком объясняется домашним каналом, GRE/каскад добавляют ноль. Если напрямую качает 800+ — возвращаться к greHOME-ноге.

Курьёзы, пойманные при замерах (свойства ноды, каскаду не мешают):
- прямые исходящие ноды в «чужой» интернет частично мертвы (TCP-таймауты к крупным публичным сервисам, DNS резолвится через раз) — нода «умеет» только своих (hop, GRE-соседи); юзерскому трафику это не нужно, он весь уходит через hop (см. 6.4);
- `iperf3 -R` без лимита (одиночный поток, попытка ~1+ Гбит) убивается, @800M проходит стабильно — похоже на полисер входящего с жёстким kill выше ~800–900;
- один контрольный прогон @400M передал 0 байт при «успешном» отчёте (не воспроизведён; подозрение на гонку сразу после добавления ufw-правила).

---

## 4. ICMP-вариант (pingtunnel): как поднимался и почему похоронен

### 4.1 Конфигурация

Сервер на ноде (`/etc/systemd/system/pingtunnel.service`):

```ini
[Unit]
Description=Pingtunnel ICMP server (TCP-over-ICMP to local xray)
After=network.target xray.service

[Service]
Type=simple
User=root
ExecStart=/opt/pingtunnel/pingtunnel -type server -key <ICMP_KEY> -noprint 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Клиент (Windows, admin-cmd):

```
pingtunnel.exe -type client -l :17443 -s <NODE_IP> -t 127.0.0.1:443 -tcp 1 -key <ICMP_KEY>
```

v2rayN: профиль на `127.0.0.1:17443`. В PowerShell запускать `.\pingtunnel.exe` (не из текущей папки без префикса). Нужны права администратора (raw ICMP-сокеты).

### 4.2 Что вышло на практике (провал и его причины)

- В простое канал идеален: pong ~14 мс, соединение поднимается.
- При включении прокси (браузер открывает десятки соединений разом) поток ICMP-пакетов упирается в **рейт-полисер пути домашнего ISP**: обратка (даже pong-кадры) пропадает через ~1 с после старта, клиент enters retransmit-шторм (дефолт `-tcp_rst 400мс` даёт x5 к потоку) и добивает канал окончательно.
- Тюнинг клиента (`-tcp_rst 2000 -tcp_mw 6000`) снял шторм, но не спас: серверная сторона видела, что пакеты клиента ДОХОДЯТ, соединения поднимаются, нода отдаёт данные (пик 178 соединений, 153 КБ/с) — и поток умирает разом. Полисер с малым burst, режется весь поток.
- Нагрузочный тест с промежуточного зарубежного хоста: 300/300 параллельных соединений — 100% успех. Значит сервер ноды и её ICMP-инбаунд абсолютно здоровы; **умирает именно путь к домашнему ISP под нагрузкой**.

**Вывод:** ICMP-туннель — только аварийный канал (одна страница/мессенджер), не основной. Причина асимметрии down/up у GRE-варианта к ICMP не относится.

### 4.3 Полезные флаги pingtunnel, выясненные в процессе

`-tcp_rst <ms>` (ретрансмиссия, дефолт 400 — источник шторма), `-tcp_mw <win>` (макс. окно, дефолт 20000), `-tcp_bs <bytes>` (буфер), `-congestion` (алгоритм, дефолт bb), `-maxprt/-maxprb` (потоки на сервере, дефолты 100/1000 — НЕ являются узким местом, проверено нагрузкой).

---

## 5. Резервные транспорты, если GRE задушат

Если фильтр хостера начнёт резать proto 47 (или транзит домашнего ISP), порядок проб:

### Приоритет 1: IPIP (proto 4)

Настройка практически идентична GRE (тот же `ip tunnel`, `mode ipip` вместо `mode gre`), инкапсуляция на 4 байта тоньше. Несёт только unicast IPv4 — для наших целей достаточно. Ничем не «шифруется», но фильтру нечего разбирать, кроме заголовка proto 4.

### Приоритет 2: ESP / IPsec без IKE (proto 50)

Выглядит как обычный IPsec-трафик (самый «не вызывающий подозрений» вариант). Нюанс: **IKE (UDP 500/4500) с ноды наружу мёртв** (исходящий UDP за рубеж дропается) — значит только **ручные ключи через `ip xfrm`** (state/policy с spi/aes/sha вручную на обеих сторонах), без strongswan-IKE. Сложнее в обслуживании (ротация ключей руками), но живёт вне UDP.

### Приоритет 3: SIT (proto 41)

IPv6-in-IPv4. Экзотика, но если фильтр точечно душит 47 — как вариант с тем же `ip tunnel add ... mode sit`.

### Гибридный запасной: ICMP-нога до промежуточного хоста + GRE дальше

Если именно путь «домашний ISP → нода» полисит GRE (а не фильтр хостера): ICMP-туннель до промежуточного зарубежного хоста (другой транзит), от него — GRE до ноды. Меняет транзит, оставляя ноду entry. Скорость ~0.9–7 Мбит/с (ICMP-нога), но живо.

### Чего НЕ пробовать (доказано мёртвым)

- **WireGuard / VXLAN / OpenVPN-UDP / QUIC / H3-прокси** — любой UDP-инбаунд мёртв, исходящий UDP за рубеж мёртв.
- **TCP-туннели напрямую к ноде** (OpenVPN-TCP, любые TCP-прокси) — payload-дроп после хендшейка; IP-фрагментация спасает только первый бёрст.
- **Серверные техники против фильтра** (desync/mss/window/RST-игры) — 11 конфигураций, нулевой эффект: фильтр апстримный.

### Методика проверки нового протокола (30 минут)

1. tcpdump на NIC ноды: `-p <proto>` — видны ли пакеты от тестового хоста на входе.
2. 100 пингов/пакетов sustained внутри туннеля — 0% loss.
3. Полный TLS/VLESS E2E через туннель.
4. Нагрузка 100–300 параллельных соединений с промежуточного хоста.
5. Тест с домашнего пути (транзит ISP — отдельная переменная, см. 4.2).

Последнее средство — перенос entry-роли на другую ноду.

---

## 6. Операционка

### 6.1 Доступ к ноде при лежащем прямом SSH

Прямой SSH к ноде рвётся тем же фильтром (TCP-payload). Рабочий паттерн — **через exit-A по GRE** (на exit-A поднят зеркальный grepl, у ноды `ufw allow in on grepl`):

```bash
ssh -J root@<EXIT_A_IP> root@10.0.0.1
```

### 6.2 Мониторинг

```bash
systemctl is-active xray grepl grepl-keepalive grehome pingtunnel
ip -s link show greHOME          # RX/TX байты, errors/dropped должны быть 0
ping -c 5 10.0.0.6               # роутер (нужен INPUT-allow на Merlin)
ss -tnp | grep -c xray           # активные соединения
```

### 6.3 Полный разбор (teardown)

Нода: `systemctl disable --now grehome grepl grepl-keepalive pingtunnel && ip tunnel del greHOME && ip tunnel del grepl` (+ убрать before.rules строку и per-interface ufw-правила, если навсегда).
Роутер: `ip tunnel del greHOME` + удалить `/jffs/scripts/gre-home.sh` и строку из `wan-start` + перезагрузка роутера (снимет iptables-правила).

### 6.4 Особенность: прямые исходящие ноды в интернет ограничены

Замечено при замерах 2026-10-10: с ноды не коннектятся (TCP-таймаут) крупные публичные веб-сервисы, DNS резолвится частично; при этом hop-бокс и GRE-соседи доступны на полной скорости (3.65 Гбит/с). Каскаду это не мешает — весь исходящий пользовательский трафик уходит через hop. Следствия: (а) `apt`/обновления с ноды напрямую могут не работать — пакеты ставить заранее или через hop-прокси; (б) диагностику «нода → внешний интернет» не считать сигналом проблемы: health-check ноды = связность с hop (ping по GRE + VLESS-коннект), а не с внешним миром.

---

## 7. Чеклист восстановления с нуля (condensed)

1. Проверить предусловия роутера: белый IP, `modprobe ip_gre`, тестовый tunnel add/del (3.1).
2. Нода: `/etc/gre-home-remote` = IP роутера; скрипты + `grehome.service` (2.3); `ufw allow in on greHOME`; proto 47 в before.rules (2.4).
3. Роутер: разовый блок 3.3 → ping `10.0.0.5` = 0% loss.
4. Роутер: автозапуск 3.4.
5. Клиент: vless-профиль на `10.0.0.5:443` (3.5), проверка IP + скорость.
6. Если прямой путь лежит/задушен — резервные транспорты по разделу 5.
7. xray-инбаунд и каскад (2.6) живут на ноде независимо от GRE; при пересоздании с нуля — собирать по скелетам 2.6 (креды экзитов восстанавливать из своего менеджера секретов, в конфиге они в открытом виде).

