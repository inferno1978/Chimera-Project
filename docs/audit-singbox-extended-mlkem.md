# Аудит: sing-box-extended (shtorm-7) — решает ли проблему MLKEM768 + FP=Firefox

**Дата:** 2026-09-12
**Метод:** сравнительный аудит фингерпринтного (uTLS) слоя четырёх ядер по первоисточникам: клон `shtorm-7/sing-box-extended` (ветка `extended`, HEAD `6a6a1e0` от 2026-09-05), raw-файлы официального `SagerNet/sing-box` (master), raw-файлы `MetaCubeX/mihomo` (Meta), клон `Xray-core`; плюс распакованные tarball-ы ОБЕИХ веток uTLS — `metacubex/utls v1.8.7` и `refraction-networking/utls v1.8.3-0.20260301010127` (снапшот 2026-03-01). Каждое утверждение сопровождается ссылкой `file:line` на первоисточник.
**Вопрос:** форк `sing-box-extended` позиционируется как «sing-box with extended features» (WARP, MASQUE, MTProxy, Mieru, TrustTunnel, Sudoku, SSH, Call, лимитеры и т.д.). Клиентская сторона Химеры сейчас работает гибридом «Clash Verge + xray-ядро» именно из-за проблемы MLKEM768 + FP=Firefox (см. [`docs/faq/VLESS_FAQ.md`](faq/VLESS_FAQ.md) §18). Если форк починил фингерпринтный слой — гибрид можно было бы перевести на одно ядро.
**Короткий ответ:** **НЕТ, не решает.** Фингерпринтный слой форка побайтово идентичен официальному sing-box (и mihomo): та же библиотека `metacubex/utls v1.8.7`, тот же маппинг `firefox → HelloFirefox_Auto = HelloFirefox_120` — спека Firefox 120 (декабрь 2023) **без** post-quantum. Более того, REALITY-клиент sing-box (и форка) **безусловно вырезает** X25519MLKEM768 из ClientHello при любом фингерпринте. Гибрид «Clash Verge + xray-ядро» остаётся правильным решением.

---

## 1. Контекст: в чём проблема

Серверы Xray-core MLKEM-эпохи (26.9.8/26.9.9, см. §18 VLESS_FAQ: матрица совместимости) требуют в ClientHello key_share **X25519MLKEM768 первой позицией** — рукопожатия без него (или с ним не в первой позиции) отвергаются (`reality verification failed`, наружу — 502/Timeout). Реальный Firefox ≥128 шлёт X25519MLKEM768 в ClientHello по умолчанию (PQ-эпоха браузеров). Поэтому:

- клиент с фингерпринтом `firefox`, собранный по спеке Firefox 120 (2023, до PQ), на MLKEM-сервере **отваливается** — и, что не менее важно, **не соответствует реальному Firefox**, т.е. палится на точном сравнении ClientHello;
- mihomo научился MLKEM только «рецептом B»: `fp=chrome` + `reality-opts.support-x25519mlkem768: true` (генераторы Chimera пишут его автоматически с 10.09.2026) — но **не** с `fp=firefox`;
- Xray-core умеет MLKEM с `fp=chrome/firefox/safari` — его спека Firefox современная (148, с PQ). Отсюда текущий гибрид: Clash Verge как оболочка/менеджер подписок + xray-ядро как транспорт.

Вопрос аудита: не добавил ли `sing-box-extended` свежих Firefox-спек с PQ (или иного пути слать MLKEM с firefox-фингерпринтом).

## 2. Методика — что сверялось

| # | Артефакт | Что извлечено |
|---|---|---|
| 1 | `shtorm-7/sing-box-extended`, клон, ветка `extended`, HEAD `6a6a1e0` (2026-09-05) | `go.mod` (какая uTLS-библиотека), карта фингерпринтов `common/tls/utls_client.go`, REALITY-клиент `common/tls/reality_client.go`, опция `CurvePreferences` `option/tls.go`, README |
| 2 | `SagerNet/sing-box`, master, raw | те же четыре файла — сверка «форк vs официоз»: что форк реально меняет |
| 3 | `metacubex/utls v1.8.7`, tarball | `u_common.go` (что стоит за `HelloFirefox_Auto` / `HelloChrome_Auto`), `u_parrots.go` (спеки FF120 / Chrome133: SupportedCurves, KeyShares) |
| 4 | `refraction-networking/utls v1.8.3-0.20260301010127`, tarball | то же для FF148 — эталон «Firefox с PQ» |
| 5 | `MetaCubeX/mihomo` (Meta), raw + `Xray-core`, клон | `go.mod` + карта фингерпринтов — позиционирование гибрида |

Сеть для клонов — прямая; raw-файлы GitHub доступны без токена.

## 3. Сводная таблица: «firefox» в четырёх ядрах

| Ядро | uTLS-зависимость (go.mod) | `firefox` маппинг | Спека за `firefox` | X25519MLKEM768 в ClientHello? |
|---|---|---|---|---|
| **sing-box-extended** (shtorm-7, 6a6a1e0) | `metacubex/utls v1.8.7` (`go.mod:41`; Go 1.26.4, `go.mod:3`) | `utls.HelloFirefox_Auto` (`common/tls/utls_client.go:377-378`) | **Firefox 120** (дек. 2023): curves X25519, P-256, P-384, P-521, FFDHE2048, FFDHE3072 (`u_parrots.go:1376-1384`); key_share X25519 + P-256 (`u_parrots.go:1408-1411`) | **НЕТ** |
| **sing-box официальный** (SagerNet, master) | `metacubex/utls v1.8.7` (`go.mod:29`; Go 1.25.5) | идентично форку — `utls_client.go` **побайтово совпадает** (diff = 0 строк) | та же FF120 | **НЕТ** |
| **mihomo** (MetaCubeX, Meta) | `metacubex/utls v1.8.7` (`go.mod:49`) | `utls.HelloFirefox_Auto` (`component/tls/utls.go:80`) | та же FF120 | **НЕТ** (MLKEM — только «рецепт B» с `fp=chrome`) |
| **Xray-core** | `refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af` (`go.mod:19`; Go 1.27) | `&utls.HelloFirefox_Auto` (`transport/internet/tls/tls.go:206`) + **версионые** `hellofirefox_120` / `hellofirefox_148` (`tls.go:221-222`) | **Firefox 148**: curves **X25519MLKEM768 первой**, X25519, P-256, P-384, P-521, FFDHE (`u_parrots.go:1501-1509`); key_share `ReuseHybridAndClassicalKeyShares(X25519MLKEM768 + X25519)` + P-256 (`u_parrots.go:1532-1545`) | **ДА** |

Эталон для сравнения — что шлёт реальный Firefox: X25519MLKEM768 первой позицией в supported_groups и в key_share. Спека FF148 (refraction) этому соответствует, FF120 (metacubex) — нет.

## 4. Факт 1: фингерпринтный слой форка НЕ тронут

`common/tls/utls_client.go` форка **побайтово идентичен** официальному `SagerNet/sing-box` master (сверка diff — 0 строк). Это включает карту фингерпринтов целиком:

```go
// sing-box-extended/common/tls/utls_client.go:375-378
	case "chrome", "":
		utls.HelloChrome_Auto,
	case "firefox":
		return utls.HelloFirefox_Auto, nil
```

Идентичность одного файла — не доказательство сама по себе, но она же подтверждается зависимостью: та же библиотека `metacubex/utls v1.8.7` в `go.mod` (`sing-box-extended/go.mod:41` против официального `go.mod:29`). В ветке metacubex на момент аудита свежих Firefox-спек с PQ нет вовсе: `HelloFirefox_Auto = HelloFirefox_120` (`metacubex-utls/u_common.go:605`), набор версионных ID заканчивается на FF120; на master метакубекса `Auto` тоже = 120. То есть «обновить форк до свежего Firefox» нечем — ветка библиотеки отстала от реальности на ~2 года (Firefox 128+, PQ с 2024).

## 5. Факт 2: что реально стоит за «firefox» в форке

```go
// metacubex/utls v1.8.7, u_common.go:605
	HelloFirefox_Auto = HelloFirefox_120
```

```go
// metacubex/utls v1.8.7, u_parrots.go:1376-1384 (спека HelloFirefox_120)
				&SupportedCurvesExtension{
					Curves: []CurveID{
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
						256,    // FFDHE2048
						257,   // FFDHE3072
					},
				},
// u_parrots.go:1408-1411
					KeyShares: []KeyShare{
						{Group: X25519},
						{Group: CurveP256},
```

Ни в SupportedCurves, ни в KeyShares группы X25519MLKEM768 (0x11EF / 4588) нет. Это спека Firefox 120 от декабря 2023 года — до PQ-эпохи браузеров.

Для контраста — то же место в ветке refraction (Xray-core):

```go
// refraction-networking/utls, u_common.go:605,614
	HelloFirefox_Auto = HelloFirefox_148
	HelloFirefox_148  = ClientHelloID{helloFirefox, "148", nil, nil}
```

```go
// refraction-networking/utls, u_parrots.go:1501-1509 (спека HelloFirefox_148)
				&SupportedCurvesExtension{
					Curves: []CurveID{
						X25519MLKEM768,   // <-- первой позицией
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
						0x0100,
						0x0101,
					},
				},
// u_parrots.go:1532-1545
			&KeyShareExtension{
				KeyShares: append(
					ReuseHybridAndClassicalKeyShares(
						KeyShare{Group: X25519MLKEM768},
						KeyShare{Group: X25519},
					),
					KeyShare{Group: CurveP256},
				),
			},
```

Xray-core дополнительно даёт **версионый выбор** прямо в конфиге: `"hellofirefox_148"` / `"hellofirefox_120"` (`transport/internet/tls/tls.go:221-222`) — можно осознанно слать PQ-Firefox или классический FF120, а `"firefox"` (`tls.go:206`) ведёт на Auto = 148.

## 6. Факт 3: REALITY-клиент sing-box безусловно ВЫРЕЗАЕТ MLKEM

Это самая тяжёлая часть вердикта. REALITY-клиент sing-box после сборки handshake state **фильтрует** X25519MLKEM768 из ClientHello — всегда, при любом фингерпринте:

```go
// sing-box-extended/common/tls/reality_client.go:147-158
	uConn.BuildHandshakeState()
	for _, extension := range uConn.Extensions {
		if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
			ce.Curves = common.Filter(ce.Curves, func(curveID utls.CurveID) bool {
				return curveID != utls.X25519MLKEM768
			})
		}
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			ks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {
				return share.Group != utls.X25519MLKEM768
			})
		}
	}
	uConn.BuildHandshakeState()   // пересборка уже БЕЗ MLKEM
```

Следствия:

- даже если фингерпринт СПЕЦИАЛЬНО с PQ (например `chrome` → Chrome 133, где MLKEM есть — см. §8), REALITY-аутбаунд sing-box отправит ClientHello **без** MLKEM. Сервер MLKEM-эпохи (26.9.8+) такой хендшейк отвергает;
- это **upstream-поведение**, не изобретение форка: сверка с официальным `SagerNet/sing-box` master показывает, что весь MLKEM-фильтр там уже есть, а единственное отличие `reality_client.go` форка — три байта SessionId (`1,8,1` → `26,7,11`, `reality_client.go:186-188` — версия реализации XTLS, отчитывается в хендшейке);
- вывод жёстче «не решает»: sing-box (и форк) на MLKEM-серверах REALITY **не заработает в принципе** — ровно как зафиксировано в §18 VLESS_FAQ: «не работает и не заработает конфигом».

## 7. Факт 4: CurvePreferences существуют, но uTLS-клиента не касаются

В форке (как и в официозе) есть опция `curve_preferences` с X25519MLKEM768 в enum-е:

```go
// sing-box-extended/option/tls.go:162
	X25519MLKEM768 = 4588
// option/tls.go:208
	return schema.StringEnum("P256", "P384", "P521", "X25519", "X25519MLKEM768"), nil
```

Куда она применяется (grep по `CurvePreferences` в `common/tls/`):

| Файл | Строки | Потребитель |
|---|---|---|
| `std_client.go` | 175-176 | стандартный crypto/tls-клиент (без фингерпринта) |
| `system_client.go` | 40-41 | системный TLS-клиент |
| `masque_client.go` | 40-41 | MASQUE (QUIC/H2) |
| `std_server.go` | 397-398 | стандартный TLS-сервер |
| `reality_server.go` | 76 | REALITY-**сервер** |
| `utls_client.go` | — | **НЕ применяется**: спека фингерпринта фиксирована, кривые берёт спека |

То есть задать `curve_preferences: [X25519MLKEM768]` можно — но это повлияет на не-uTLS TLS-направления и на собственный сервер форка, а НЕ на клиентский фингерпринтный ClientHello. Проблему FP=Firefox+MLKEM опция не решает ни в каком виде.

## 8. Факт 5: единственная MLKEM-заготовка metacubex — Chrome

В metacubex/utls v1.8.7 спека с X25519MLKEM768 есть, но только одна — свежий Chrome:

```go
// metacubex/utls, u_common.go:615
	HelloChrome_Auto = HelloChrome_133
```

```go
// metacubex/utls, u_parrots.go:884+ (спека HelloChrome_133), curves ~914-918:
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				// keyshares ~938-940:
					{Group: X25519MLKEM768},
					{Group: X25519},
```

Поэтому `fingerprint: "chrome"` (он же дефолт, `utls_client.go:375`) в sing-box-extended на **не-REALITY** TLS-аутбаундах даёт MLKEM в ClientHello — но на REALITY-аутбаундах он вырезается фильтром из §6. У mihomo аналогичная картина оформлена флагом `support-x25519mlkem768` («рецепт B», включён по умолчанию генераторами Chimera), у Xray — полноценные спеки и `firefox`, и `chrome`, и `safari` с PQ.

## 9. Вердикт

**sing-box-extended НЕ решает проблему MLKEM768 + FP=Firefox — ни в одной из трёх позиций:**

1. **Firefox-спека без PQ**: та же `metacubex/utls v1.8.7`, `firefox → FF120` (2023) — фингерпринтный слой не менялся вовсе (файл побайтово = официозу).
2. **REALITY не умеет MLKEM вообще**: безусловный strip X25519MLKEM768 в REALITY-клиенте — upstream-дизайн, унаследован форком без изменений.
3. **Кривые настроить нельзя**: `curve_preferences` не доходит до uTLS-клиента.

Переход с гибрида на sing-box-extended **вернёт проблему в исходном виде** и добавит регресс: mihomo (текущая половина гибрида через Clash Verge) умеет «рецепт B» (chrome+флаг → MLKEM в REALITY), sing-box — не умеет ничего. Правильная архитектура остаётся прежней:

- **Clash Verge (mihomo) для не-REALITY и управления подписками** — MLKEM там, где нужен, идёт рецептом B;
- **xray-ядро для REALITY/MLKEM-направлений с честным FP=firefox** — единственное из четырёх ядер со спекой Firefox 148 (PQ), плюс версионые ключи `hellofirefox_148`/`hellofirefox_120` для тонкого контроля.

Если когда-нибудь захочется всё-таки одно ядро на базе sing-box-extended — два пути: (а) всем firefox-нодам ставить `fp=chrome` (спеки Chrome 133 у metacubex и refraction совпадают с реальностью и содержат PQ) — но это теряет Firefox-разнообразие фингерпринтов; (б) feature-request shtorm-7 на порт `HelloFirefox_148` из refraction utls (или replace-директивой в go.mod на refraction utls — но это уже не «просто применить», а пересборка с риском несовместимости API: ветки разошлись).

## 10. Бонус-инвентарь форка — что ценно ВНЕ фингерпринтной темы

Аудит попутно зафиксировал, что форк реально добавляет (README + код). Это НЕ про MLKEM, но релевантно Химере в других нишах:

| Блок | Состав | Зачем Химере |
|---|---|---|
| **WARP-аутбаунд** | Cloudflare WARP через WireGuard прямо в ядре | клиенту можно отдавать WARP-креды (wgcf) без локального wg — потребление тем же ядром, что и остальной трафик |
| **MASQUE-аутбаунд** | прокси поверх QUIC/HTTP-2 (Cloudflare) | второй путь потребления WARP-кредов, маскировка под HTTP/3 |
| **MTProxy** | сервер с FakeTLS и domain fronting | уже есть свой telemt — но форк даёт встроенную альтернативу |
| **Mieru / TrustTunnel / Sudoku / SSH / Call** | набор протоколов Химеры в апстриме sing-box | синхронизация стека: модули Химеры (trusttunnel, mieru) доступны и клиенту без отдельных бинарей |
| **VLESS-encryption / XHTTP / mKCP / Rmux** | XRAY-транспорты в sing-box | кластеризация с Xray-эпохой |
| **Amnezia 3.1** | обфускация WireGuard | AWG-ноды Химеры из коробки |
| **Лимитеры** | Bandwidth / Connection / Traffic / Rate | per-user шейпинг на уровне ядра |
| **Go 1.26.4** | свежий тулчейн (`go.mod:3`) | просто заметка о современности |

Отдельно: fork живой (HEAD 2026-09-05, merge-коммиты из upstream ветки `extended`), зеркало на Codeberg, Telegram-канал — проект не брошен. Но его траектория — протоколы и удобство, НЕ фингерпринтная точность: ни одного коммита/строки README про uTLS-спеки за всю историю сравнения с официозом (сверка `utls_client.go` — 0 строк diff).

## 11. Репродукция аудита

```bash
# 1) форк и его фингерпринтный слой
git clone --depth 1 https://github.com/shtorm-7/sing-box-extended
cd sing-box-extended
grep -n 'utls\|^go ' go.mod                       # metacubex/utls v1.8.7, go 1.26.4
grep -n '"firefox"' common/tls/utls_client.go     # :377 — HelloFirefox_Auto

# 2) сверка с официозом (фингерпринтный слой не тронут)
curl -s https://raw.githubusercontent.com/SagerNet/sing-box/master/common/tls/utls_client.go | diff - common/tls/utls_client.go
# → пусто (identical); реальность-клиент отличается только SessionId-байтами:
curl -s https://raw.githubusercontent.com/SagerNet/sing-box/master/common/tls/reality_client.go | diff - common/tls/reality_client.go
# → 186,188c186,188: SessionId 1,8,1 → 26,7,11

# 3) что за HelloFirefox_Auto в ветке metacubex (использует и форк, и mihomo)
mkdir -p /tmp/mu && tar -xzf <(curl -sL https://github.com/metacubex/utls/archive/refs/tags/v1.8.7.tar.gz) -C /tmp/mu
grep -n 'HelloFirefox_Auto\|HelloChrome_Auto' /tmp/mu/utls-1.8.7/u_common.go   # 605: Auto=120; 615: Chrome=133
sed -n '1376,1384p;1408,1411p' /tmp/mu/utls-1.8.7/u_parrots.go                 # FF120: БЕЗ MLKEM
sed -n '914,918p' /tmp/mu/utls-1.8.7/u_parrots.go                              # Chrome133: MLKEM есть

# 4) эталон с PQ — ветка refraction (использует Xray-core)
mkdir -p /tmp/ru && tar -xzf <(curl -sL https://github.com/refraction-networking/utls/archive/<snapshot-2026-03>.tar.gz) -C /tmp/ru
grep -n 'HelloFirefox_Auto' /tmp/ru/*/u_common.go                              # 605: Auto=148
sed -n '1501,1509p;1532,1545p' /tmp/ru/*/u_parrots.go                          # FF148: X25519MLKEM768 первой

# 5) позиция Xray-core: версионые ключи
grep -n '"firefox"\|hellofirefox_120\|hellofirefox_148' Xray-core/transport/internet/tls/tls.go   # 206, 221-222
```

Критерий «решает/не решает» один: содержит ли ClientHello при `fp=firefox` key_share X25519MLKEM768 первой позицией — как реальный Firefox ≥128. Ответ для sing-box-extended: нет (спека FF120), и для REALITY — нет ни при каком фингерпринте (upstream-фильтр).
