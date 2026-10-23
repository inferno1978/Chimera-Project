# ICMP Gate в Chimera — FAQ по маскировке пинга

Это гайд по модулю `chimera/modules/icmp_gate.py` — эхо-запросы (пинг)
отвечают только доверенным источникам, всем остальным — тишина («хоста
нет»).

> **Краткая суть:**
> - echo-request (пинг) от источников из allowlist → ACCEPT (ядро отвечает)
> - echo-request от всех остальных → DROP, молча («как unallocated IP»)
> - Дополнительно прячем timestamp-request (nmap -PP) и
>   address-mask-request (nmap -PM) — тоже DROP для чужих
> - Роль `exit`: allow = admin_ips + peer_ips (bridge-ноды, ICMP-партнёры)
> - Роль `entry`: allow = admin_ips только
> - PMTUD-критичные ICMP-типы НЕ трогаем никогда (валидатор запрещает)
> - Списки доверенных — в state на ноде, в репо не попадают

---

## 1. Зачем это нужно

Нода, отвечающая на пинг любому источнику, бесплатно фингерпринтится
сканерами (Censys/Shodan/Shadowserver, массовые zmap-обходы): живой хост,
аптайм-паттерн, косвенная привязка к инфраструктуре. Port Knocking уже
прячет VPN-порты от тех же сканеров; ICMP Gate закрывает оставшееся окно
по той же философии: **deny by default, доверенным — ACCEPT**.

Почему DROP, а не REJECT: молчание неотличимо от несуществующего адреса;
любой ответ (даже «host unreachable») доказывает, что IP занят и кто-то
его фильтрует осознанно.

## 2. Роли и списки доверья

| Роль | Кто может пинговать ноду | Кого указывать |
|---|---|---|
| `exit` | admin_ips + peer_ips | в peer_ips — bridge/entry-ноды каскада (мониторинг увидит их RTT) и ICMP-партнёры (GRE/pingtunnel-relay: их ICMP-fallback ходит эхо-запросами в обе стороны) |
| `entry` | admin_ips только | peer_ips игнорируются (модуль предупредит) |

Списки — IP/CIDR (v4+v6), хранятся в
`/var/lib/xray-installer/icmp_gate.json` на самой ноде. Инфраструктурные
адреса не должны попадать в репозиторий (см. SECURITY_LEAK_POLICY —
зеркала публичные).

## 3. Механизмы (mode)

- **ufw** — managed-блок `# BEGIN/END chimera-icmp-gate` в
  `/etc/ufw/before.rules` и `before6.rules` перед сток-строкой
  `echo-request ACCEPT` + `ufw reload`. Сток-строка не удаляется (после
  нашего DROP она мёртвая), при первой модификации создаётся однократный
  бэкап `.bak-icmp-gate`. `remove()` возвращает файлы к сток-виду.
- **raw** — iptables/ip6tables-правила с comment-тегом `chimera-icmp-gate`
  в самом верху INPUT (над ban/knocking/ufw-цепочками) + пересохранение
  `/etc/iptables/rules.v4|v6` — при буте их поднимает
  `telemt-iptables.service` (тот же путь, что у port-knocking/clients-wl
  на raw-нодах). `netfilter-persistent` намеренно не используется: на
  UFW-машинах его save ломает бут.
- **auto** — детект: в INPUT есть raw-правила chimera-стека → raw,
  иначе ufw.

## 4. Что принципиально НЕ трогаем

- **PMTUD**: `destination-unreachable`, `time-exceeded`,
  `parameter-problem`, `packet-too-big` — их дроп ломает TCP
  (чёрные дыры на фрагментации). Валидатор модуля запрещает добавить их
  в `drop_types` с понятной ошибкой.
- **FORWARD-цепочку** и `ufw-before-forward` — GRE-транзит не касается
  INPUT.
- **Входящий echo-reply** — это ответы на собственные зонды ноды
  (pingtunnel-клиент, мониторинг) — их ждут обратно.
- **TCP/UDP** — knocking/clients_wl/ban-стек работают как раньше.
- **NDP и v6-PMTUD** — в IPv6 дропаем только `icmpv6-type echo-request`.

## 5. Совместимость с мониторингом

`chain_relay.icmp_rtt` и Health Matrix используют ICMP-RTT как
**информационную** колонку; вердикт UP/DOWN решает full-path зонд
(кейсы №3/№9). Источники зондов вне allowlist увидят «—» в колонке RTT —
вердикты не изменятся. Если мониторинговому хосту нужен RTT — добавьте
его в `peer_ips` на exit-нодах.

## 6. Как включить

Меню: главная → Безопасность → `IM` (рядом с Port Knocking).

Headless (деплой-скрипты):

```bash
python3 -c "from chimera.modules.icmp_gate import icmp_gate_apply; \
    icmp_gate_apply({'role':'exit','mode':'ufw', \
                     'admin_ips':['198.51.100.10'], \
                     'peer_ips':['203.0.113.20']})"
```

Проверка (машинная, для скриптов):

```bash
python3 -c "from chimera.modules.icmp_gate import icmp_gate_check, icmp_gate_status; \
    import json,sys; json.dump(icmp_gate_check(), sys.stdout, indent=2); print(); print(icmp_gate_status())"
```

Выключение:

```bash
python3 -c "from chimera.modules.icmp_gate import icmp_gate_remove; icmp_gate_remove()"
```

## 7. Идемпотентность и повторный apply

Повторный `icmp_gate_apply(...)` безопасен: raw-режим сначала вычищает
все свои правила по comment-тегу (bottom-up delete), затем вставляет
свежие в правильном порядке (allow всегда выше drop); ufw-режим вырезает
старый managed-блок и вставляет новый. Менять список доверенных =
просто вызвать apply с новыми `admin_ips`/`peer_ips`.
