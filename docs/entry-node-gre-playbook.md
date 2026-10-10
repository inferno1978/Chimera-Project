# Entry-нода за ингресс-фильтром: GRE-playbook (возрождение ноды)

**Дата:** 2026-10-10
**Статус:** конфигурация живая на ноде; документ зафиксирован post-factum, чтобы опыт не потерялся

---

## Контекст и TL;DR

Entry-нода стоит за апстрим-ингресс-фильтром хостера, который дропает **все входящие TCP-сегменты с payload** и **весь входящий UDP**, но **не трогает ICMP и GRE (IP proto 47)**. Классические инбаунды (VLESS/TLS напрямую, OpenVPN, WireGuard, anything TCP/UDP) на такой ноде невозможны в принципе: payload до приложения не доходит, UDP мёртв. Это доказано на уровне NIC (tcpdump) и 11-конфигурационной матрицей серверных техник — фильтр стоит апстримом, до машины, серверными трюками не обходится.

Решение: нода остаётся entry, но клиенты добираются до неё **через транспорты, прозрачные для фильтра**:

```
[клиент LAN] ──GRE──> [entry-нода: xray VLESS REALITY :443] ──каскад──> [hop] ──> [exit-ноды] ──> интернет
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

| Компонент | Назначение |
|---|---|
| xray VLESS TCP REALITY `:443` (слушает `*:443`) | инбаунд для клиентов (через GRE — внутренний адрес туннеля), исходящий каскад на exit-ноды (balancer/roundRobin) |
| `grepl.service` | GRE-туннель к exit-A: `10.0.0.1/30` ↔ `10.0.0.2/30`, автозапуск |
| `grepl-keepalive.service` | ping `10.0.0.2` каждые 55 с (держит conntrack живым, см. урок 2.4) |
| `grehome.service` | GRE-туннель к домашнему роутеру: `10.0.0.5/30` ↔ `10.0.0.6/30`, автозапуск |
| `pingtunnel.service` | ICMP-сервер (TCP-over-ICMP → локальный xray), запасной канал |
| b4 (v1.85.1) | установлен, **конфиг без сетов** (безопасно), web UI на `127.0.0.1:7000` |

### 2.2 GRE к exit-A (`/etc/systemd/system/grepl.service`)

```ini
[Unit]
Description=GRE tunnel to exit-A
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/grepl-up.sh
ExecStop=/usr/local/sbin/grepl-down.sh

[Install]
WantedBy=multi-user.target
```

`/usr/local/sbin/grepl-up.sh`:

```bash
#!/bin/bash
if ip tunnel show grepl 2>/dev/null | grep -q grepl; then exit 0; fi
modprobe ip_gre
ip tunnel add grepl mode gre local <NODE_IP> remote <EXIT_A_IP> ttl 64
ip addr add 10.0.0.1/30 dev grepl
ip link set grepl up
```

Keepalive (`grepl-keepalive.service`, таймер или простой цикл):

```bash
while true; do ping -c1 -W2 10.0.0.2 >/dev/null 2>&1; sleep 55; done
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
| E2E через каскад, download | ~290 Мбит/с |
| E2E через каскад, upload | ~840 Мбит/с |
| Сырой GRE нода ↔ exit-A | ~270 Мбит/с (~62 мс RTT) |
| Для сравнения: ICMP-вариант | ~7 Мбит/с, умирает под нагрузкой |

Сам GRE ничего не режет: оверхед 24 байта (~1.7%), шейпинга в туннеле нет. Асимметрия down/up разобрана отдельно в 3.7.

### 3.7 Асимметрия down/up (~300 вниз / ~840–900 вверх): разбор

Отдача ~840–900 Мбит/с идёт через тот же GRE, тот же роутер и тот же домашний путь — значит инкапсуляция, CPU роутера, аплинк «из дома» и ингресс ноды со стороны дома узкими местами НЕ являются. Потолок сидит на пути скачивания: `exit → нода → GRE → дом`. Кандидаты, в порядке правдоподобия:

1. **Ингресс международного транзита у хостера ноды (~300 Мбит).** Хостер уже доказал ингресс-политику жёстким фильтром (раздел 1); рейт-полисер поверх неё — логичное продолжение. Косвенное подтверждение: сырой GRE до exit-A давал те же ~270 Мбит/с (§3.6). Направление «зарубежный транзит → нода» режется, «домашний ISP → нода» — нет (отдача через GRE это доказывает).
2. **Ингресс к дому у домашнего ISP.** Прецедент есть — ICMP-полисер (§4.2). Проверяется за минуту: прямой замер скорости без прокси с того же устройства; если напрямую качает заметно больше 300 — кандидат отпадает.
3. **Каскад/xray-релеи и окно TCP при E2E RTT ~100 мс** — вторичный фактор: ограничивает одиночный поток (BDP ~3.5 МБ на 300 Мбит/с), но не объясняет трёхкратную разницу на замере со многими соединениями.

**Дискриминирующие тесты** (по возрастанию усилий):

| # | Тест | Интерпретация |
|---|---|---|
| 1 | Спидтест без прокси, то же устройство | качает >300 вниз → ингресс к дому чист, подозреваем хостера |
| 2 | `iperf3` с LAN-машины до `10.0.0.5` (туннельный адрес ноды, роутер сам заворачивает в GRE) в обе стороны (флаг `-R`) — минуя каскад | вниз ~300 / вверх ~900 → потолок на ноге дом↔нода; обе ~900 → потолок на международной ноге ноды |
| 3 | `iperf3` нода↔exit в обе стороны | локализует международную ногу независимо от дома |
| 4 | Сравнить GRE с IPIP (раздел 5) | одинаковый потолок → полисинг не привязан к proto 47 |

**Практический вывод:** для резервного входа 300/900 — отличный результат (прямой инбаунд даёт 0), оптимизация не требуется. Тесты выше нужны, только если канал деградирует или захочется выжать максимум.

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

---

## 7. Чеклист восстановления с нуля (condensed)

1. Проверить предусловия роутера: белый IP, `modprobe ip_gre`, тестовый tunnel add/del (3.1).
2. Нода: `/etc/gre-home-remote` = IP роутера; скрипты + `grehome.service` (2.3); `ufw allow in on greHOME`; proto 47 в before.rules (2.4).
3. Роутер: разовый блок 3.3 → ping `10.0.0.5` = 0% loss.
4. Роутер: автозапуск 3.4.
5. Клиент: vless-профиль на `10.0.0.5:443` (3.5), проверка IP + скорость.
6. Если прямой путь лежит/задушен — резервные транспорты по разделу 5.

