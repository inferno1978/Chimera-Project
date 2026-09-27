# WPP Web Panel — FAQ по установке, конфигурации и объединению панелей

Полный гайд по WPP (Web Panel Proxy) — админ-панели и пользовательского
портала Chimera. Описывает объединение Admin Panel и User Portal в единую
панель WPP, все возможности, доступы и архитектуру.

> **WPP** — веб-панель управления VPN-подключениями (VLESS/Hysteria2/AWG/
> MTProto/OpenFlux). Порт проекта POLESNIESOVETI12/web-panel-proxy v2.4.2
> (MIT), расширенный для Chimera. Работает на порту 9745 через nginx
> reverse-proxy с TLS (Let's Encrypt). Не путать с b4 Web UI (порт 9743) —
> это отдельная панель для DPI-bypass, см. [DPI_BYPASS_FAQ.md](DPI_BYPASS_FAQ.md).

---

## Оглавление

1. [Что такое WPP и зачем нужно объединение](#1-что-такое-wpp-и-зачем-нужно-объединение)
2. [Нужна ли отдельная установка Admin Panel и User Portal](#2-нужна-ли-отдельная-установка-admin-panel-и-user-portal)
3. [Административная часть — возможности Admin Panel](#3-административная-часть--возможности-admin-panel)
4. [Клиентская часть — возможности User Portal](#4-клиентская-часть--возможности-user-portal)
5. [Сравнительная таблица возможностей](#5-сравнительная-таблица-возможностей)
6. [Ссылки и доступ](#6-ссылки-и-доступ)
7. [Архитектура и файлы](#7-архитектура-и-файлы)
8. [Авто-обновление и защита твиков](#8-авто-обновление-и-защита-твиков)
9. [Вопросы и ответы](#9-вопросы-и-ответы)

---

## 1. Что такое WPP и зачем нужно объединение

Ранее в chimera существовало **два независимых веб-сервиса**:

| Сервис | Порт | Что обслуживал |
|--------|------|----------------|
| `vless-web.service` (rest_api.py) | 8443 | Admin Panel (`/admin/`), User Portal (`/portal/`), REST API (`/api/*`) |
| `wpp-web.service` (wpp_panel_web.py) | 9744→9745 | WPP Admin Panel (`/panel/*`) |

Два сервиса = два порта, два процесса, две точки отказа, две конфигурации
nginx. Теперь — **один сервис** `wpp-web.service` на порту 9745 обслуживает
всё: Admin Panel, User Portal и REST API.

**Объём перенесённого кода:** ~2031 строк нового кода (3 коммита).

---

## 2. Нужна ли отдельная установка Admin Panel и User Portal

**Нет.** Если установлена WPP, администратор получает:

- **Admin Panel** — `/panel/` (dashboard, клиенты, ноды, настройки, health,
  backup, GeoIP, b4, rotate UUID/REALITY, user actions)
- **User Portal** — `/portal/` (10 табов: конфиги, подписки, трафик, IP,
  пароль, сателлиты, b4, сервер, AmneziaWG)
- **REST API** — `/api/*` (health, rotate, backup, geoip, portal, b4, sat, awg)

Устанавливать `vless-web.service` (rest_api.py) отдельно **не нужно**.
Файл `rest_api.py` остаётся в chimera source как библиотека — helper-функции
импортируются в `wpp_portal.py`.

Если `vless-web.service` уже установлен — удалите:
```bash
systemctl stop vless-web
systemctl disable vless-web
rm /etc/systemd/system/vless-web.service
systemctl daemon-reload
```

---

## 3. Административная часть — возможности Admin Panel

**Вход:** `https://<домен>:9745/panel/login` → логин `admin` → пароль.

| Раздел | URL | Возможности |
|--------|-----|------------|
| **Dashboard** | `/panel/dashboard` | Статистика сервера (трафик, подключения, RAM, disk) |
| **Клиенты** | `/panel/users` | Создание/удаление/бан/переименование/смена пароля/ротация UUID |
| **Ноды** | `/panel/nodes` | Добавление cascade-нод (VLESS+REALITY), federation-нод, управление локациями |
| **Настройки** | `/panel/settings` | Смена админ-пароля, landing editor, пресеты, health, backup, GeoIP, b4 |
| **Обновления** | `/panel/updates` | Проверка/установка версий WPP + Xray + OpenFlux |
| **Подписки** | `/panel/subscriptions` | Multi-node подписки (mihomo/sing-box), QR-коды |
| **OpenFlux** | `/panel/openflux` | Управление multi-profile OpenFlux |

В профиле клиента (клик по юзеру) — кнопки:
- 🔄 Сменить UUID
- 🔨 Ban / Unban
- 🔑 Портальный пароль (мин. 8 символов)
- ✏️ Переименование (3-32 символа)

В Настройках — виджеты:
- 📊 Health (xray/nginx/dnscrypt, SSL дней, CPU, uptime, RAM, disk, connections)
- 🗄️ Backup (создать/просмотреть)
- 🌐 GeoIP (country block/allowlist)
- 📡 b4 (install/enable/disable/discovery)

---

## 4. Клиентская часть — возможности User Portal

**Вход:** `https://<домен>:9745/portal/` → email + portal_password.

Также доступен **авто-логин по UUID**: `https://<домен>:9745/portal/<uuid>`
— пользователь кликает ссылку и сразу попадает в портал без ввода пароля.

10 вкладок:

| Tab | Что показывает |
|-----|---------------|
| 🔗 Подключение | VLESS-ссылка, QR-код, гайд по клиентам (iOS/Android/Windows/Mac/Linux) |
| 📚 Подписка | Multi-node подписки (mihomo YAML, sing-box JSON, base64 URL) |
| 📥 Конфиги | Скачать Clash Meta / sing-box / Hiddify / VLESS-ссылку |
| 📊 Трафик | Получено/отправлено/всего, лимиты, TTL |
| 🛂 IP | IP whitelist (добавить/закрепить/открепить/заменить все) |
| 🔒 Пароль | Смена portal password |
| 🛰 Сателлиты | Привязки протоколов (Mieru/NaiveProxy/Telemt/TrustTunnel/sing-box) |
| 📺 YouTube DPI | Статус b4 (DPI bypass) для пользователя |
| 🖥 Сервер | Информация о сервере (домен, порт, протокол, SSL, аптайм) |
| 🛡 AmneziaWG | Конфигурация AWG (если установлен) |

Скрытые табы (появляются при наличии соответствующих сервисов):
- 📚 Подписка — при multi-node конфигурации
- 🛰 Сателлиты — при установленных сателлитных протоколах
- 📺 YouTube DPI — при включённом b4
- 🛡 AmneziaWG — при установленном AWG

---

## 5. Сравнительная таблица возможностей

| Возможность | Admin Panel (rest_api, удалён) | User Portal (rest_api, удалён) | WPP (теперь) | Статус |
|-------------|-------------------------------|-------------------------------|--------------|--------|
| Dashboard / статистика | ✅ glassmorphism | ❌ | ✅ WPP dashboard | Объединено |
| Управление клиентами | ✅ create/delete/toggle/rename | ❌ | ✅ всё + UI кнопки | Объединено |
| Ротация UUID | ✅ | ❌ | ✅ + кнопка в профиле | Перенесено |
| Ротация REALITY | ✅ | ❌ | ✅ | Перенесено |
| Health (детальный) | ✅ | ✅ (ограниченный) | ✅ оба + виджет | Перенесено |
| Backup | ✅ create/list | ❌ | ✅ + UI | Перенесено |
| GeoIP rules | ✅ GET/POST/DELETE | ❌ | ✅ + UI | Перенесено |
| b4 management | ✅ install/enable/disable | ✅ b4-info (статус) | ✅ оба | Перенесено |
| AWG management | ✅ | ✅ AWG конфиг | ✅ оба | Перенесено |
| Satellite bindings | ✅ admin bind/unbind | ✅ user sat-info/bind/unbind | ✅ оба | Перенесено |
| User Portal (HTML) | ❌ | ✅ glassmorphism | ✅ WPP-style (тёмная тема) | Переписано |
| VLESS-ссылки + QR | ❌ | ✅ | ✅ | Перенесено |
| Config downloads | ❌ | ✅ clash/singbox/hiddify | ✅ | Перенесено |
| Multi-node подписки | ❌ | ✅ sub-clash/singbox | ✅ | Перенесено |
| IP whitelist | ❌ | ✅ ips/pin/unpin/replace | ✅ | Перенесено |
| Смена пароля (user) | ❌ | ✅ | ✅ | Перенесено |
| Авто-логин по UUID | ❌ | ✅ /portal/{token} | ✅ /portal/{uuid} | Перенесено |
| Cookie auth (вместо Basic) | ❌ | ❌ | ✅ HMAC cookie | **Улучшено** |
| Cascade node form | ❌ | ❌ | ✅ (изначально в WPP) | WPP-only |
| Fingerprint dropdown | ❌ | ❌ | ✅ (11 опций) | **Новое** |
| VLESS URL auto-fill | ❌ | ❌ | ✅ (JS парсер) | **Новое** |
| Node API federation | ❌ | ❌ | ✅ (изначально) | WPP-only |
| OpenFlux management | ❌ | ❌ | ✅ (изначально) | WPP-only |
| Landing page editor | ❌ | ❌ | ✅ (изначально) | WPP-only |
| Component installer | ❌ | ❌ | ✅ (изначально) | WPP-only |
| Updates page | ❌ | ❌ | ✅ WPP+Xray+OpenFlux | WPP-only |
| Admin HTML (glassmorphism) | ✅ | ❌ | ❌ (заменён WPP) | Выпало (WPP лучше) |
| Subscription info (admin API) | ✅ | ❌ | ⚠️ через WPP UI | Эквивалент |
| Users sync (config→json) | ✅ | ❌ | ⚠️ WPP manages directly | Эквивалент |

---

## 6. Ссылки и доступ

### Admin Panel

```
URL:    https://<домен>:9745/panel/login
Логин:  admin
Пароль: <устанавливается при установке WPP>
```

Сменить пароль: Admin Panel → Настройки → "Новый пароль" → Сохранить.

### User Portal

```
URL:    https://<домен>:9745/portal/
Логин:  <email пользователя>
Пароль: <portal_password, задаётся админом>
```

Авто-логин (без ввода пароля):
```
https://<домен>:9745/portal/<UUID пользователя>
```

UUID берётся из VLESS-ссылки пользователя — администратор даёт ссылку,
пользователь кликает и сразу видит свои конфиги.

### REST API

Все API endpoints требуют admin cookie (для admin endpoints) или
portal cookie (для portal endpoints). Пример:

```bash
# Health (admin)
curl -sk -b cookie.txt https://<домен>:9745/api/health

# Backup list (admin)
curl -sk -b cookie.txt https://<домен>:9745/api/backup/list

# User links (portal, с portal cookie)
curl -sk -b portal_cookie.txt https://<домен>:9745/api/portal/links
```

---

## 7. Архитектура и файлы

```
                    ┌─────────────────────────────────┐
                    │   nginx (port 9745, TLS, LE)    │
                    │   chimera-wpp-nginx vhost       │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │  wpp-web.service (port 9744)    │
                    │  wpp_panel_web.py               │
                    │                                 │
                    │  ┌─────────┐  ┌──────────────┐ │
                    │  │ Admin   │  │ User Portal  │ │
                    │  │ /panel/ │  │ /portal/     │ │
                    │  └─────────┘  └──────────────┘ │
                    │                                 │
                    │  ┌─────────────────────────────┐│
                    │  │ REST API /api/*             ││
                    │  │ health, rotate, backup,     ││
                    │  │ geoip, b4, sat, awg,       ││
                    │  │ portal/* (links, traffic,  ││
                    │  │ configs, ips, password)    ││
                    │  └─────────────────────────────┘│
                    └─────────────────────────────────┘
```

| Файл | Назначение |
|------|-----------|
| `wpp_panel_web.py` | Backend HTTP handler (routing, auth, session) |
| `wpp_ui.py` | HTML rendering (dashboard, users, nodes, settings, portal) |
| `wpp_portal.py` | User Portal (auth, 10 tabs, 20+ API endpoints) |
| `wpp_admin_extras.py` | Admin API gaps (health, rotate, backup, geoip, b4, sat, awg) |
| `wpp_panel.py` | TUI menu для установки/управления WPP |
| `wpp_nodes.py` | Node management (cascade + federation) |
| `wpp_state.py` | state.json load/save |
| `wpp_mirrors.py` | Mirror ladder для скачивания WPP |
| `wpp_packages.py` | PackageSpec для download_manager |
| `wpp_autoupdate.py` | Auto-update cron (отключено) |
| `rest_api.py` | Helper-функции (импортируются wpp_portal) |

---

## 8. Авто-обновление и защита твиков

**Авто-обновление WPP отключено** (`auto_update.enabled = false`).

Причина: upstream `POLESNIESOVETI12/web-panel-proxy` удалён с GitHub (404).
Cron `/etc/cron.d/wpp-autoupdate` остаётся установленным, но
`wpp_autoupdate_cron()` сразу return'ит при `enabled=false`.

**Python-модули** (`wpp_ui.py`, `wpp_panel_web.py`, `wpp_portal.py`,
`wpp_admin_extras.py`) обновляются через `git pull` chimera-репозитория,
а НЕ через WPP auto-update. Все твики (fingerprint dropdown, VLESS URL
auto-fill, cascade node form, User Portal, admin gap UI) — в chimera git
и не затираются auto-update.

Если upstream воскреснет — включить авто-обновление:
`state.auto_update.enabled = true` через TUI или MCP. Но: auto-update
обновляет только `wpp_panel_www/` (статический кеш), а НЕ chimera-модули.

---

## 9. Вопросы и ответы

### Общие вопросы

**Q: Что такое WPP?**
A: WPP (Web Panel Proxy) — веб-панель управления VPN-подключениями. Порт проекта `POLESNIESOVETI12/web-panel-proxy` v2.4.2 (MIT), адаптированный для Chimera. Работает на порту 9745 через nginx reverse-proxy с TLS. Управляет пользователями VLESS/Hysteria2/AWG/MTProto/OpenFlux, трафиком, подписками, нодами и компонентами.

**Q: Зачем объединять Admin Panel и User Portal в WPP?**
A: Раньше было два сервиса на двух портах (8443 + 9745) — два процесса, две точки отказа, две конфигурации nginx. Объединение упрощает: один порт, один процесс, одна конфигурация. Администратор и пользователи заходят на один URL, но в разные разделы (`/panel/` для админа, `/portal/` для юзера).

**Q: Если установлен WPP, нужна ли отдельная установка Admin Panel и User Portal?**
A: Нет. WPP теперь содержит всё: Admin Panel (`/panel/`), User Portal (`/portal/`), REST API (`/api/*`). Устанавливать `vless-web.service` (rest_api.py) отдельно не нужно. Файл `rest_api.py` остаётся в chimera source как библиотека.

**Q: У меня уже установлен vless-web (rest_api). Что делать?**
A: Удалите `vless-web.service` — всё его функциональность теперь в WPP. Файл `rest_api.py` не удаляйте — он используется как библиотека (helper-функции импортируются WPP).

**Q: Что выпало из WPP по сравнению со старым Admin Panel?**
A: Только HTML-страница Admin Panel в glassmorphism-стиле (заменена WPP dashboard, который функциональнее). Все API endpoints и функции перенесены полностью. Subscription info (admin API) доступен через WPP UI, users sync — через WPP's own user management.

### Административная часть

**Q: Как зайти в Admin Panel?**
A: `https://<домен>:9745/panel/login` → логин `admin` → пароль (устанавливается при установке WPP или меняется в Настройках).

**Q: Как сменить админ-пароль?**
A: Admin Panel → Настройки → "Новый пароль" → Сохранить. Минимум 3 символа. Смена пароля завершает все активные сессии.

**Q: Где кнопки Rotate UUID / Ban / Rename / Set Password?**
A: Кликните на клиента в списке → откроется детальный профиль → внизу раздел "🔐 Администратор" с кнопками.

**Q: Где Health / Backup / GeoIP / b4?**
A: Admin Panel → Настройки → прокрутите вниз → раздел "Инструменты администратора" с 4 карточками.

**Q: Как создать бэкап?**
A: Настройки → 🗄️ Бэкапы → "Создать бэкап". Бэкап создаётся в `/var/backups/xray/` через `backup_rollback.create_backup()`.

**Q: Как ротировать UUID?**
A: В профиле клиента → 🔄 Сменить UUID. Старый UUID перестанёт работать — клиенту нужно обновить VLESS-ссылку. Изменения синхронизируются с xray config.json.

**Q: Как забанить пользователя?**
A: В профиле клиента → 🔨 Ban. Пользователь не сможет подключиться, но его конфигурация сохраняется. Unban — там же.

### Клиентская часть

**Q: Как пользователь заходит в User Portal?**
A: Два способа:
1. Вручную — `https://<домен>:9745/portal/` → ввести email + portal_password
2. Авто-логин — `https://<домен>:9745/portal/<UUID>` → сразу в портал без пароля

**Q: Какой пароль у пользователя?**
A: `portal_password` — задаётся админом в WPP → Клиенты → профиль клиента → "🔑 Портальный пароль". Если не задан — пользователь не сможет войти через форму (но авто-логин по UUID работает).

**Q: Может ли пользователь скачать конфиги?**
A: Да — вкладка "📥 Конфиги" в портале: Clash Meta, sing-box, Hiddify, VLESS-ссылка. Все конфиги содержат актуальные параметры (UUID, pubkey, shortId, SNI, fingerprint).

**Q: Может ли пользователь менять свой пароль?**
A: Да — вкладка "🔒 Пароль" в портале. Минимум 8 символов. Пароль меняется в `/etc/xray/users.json` (portal_password field).

**Q: Может ли пользователь управлять IP whitelist?**
A: Да — вкладка "🛂 IP". Добавить IP, закрепить (pin), открепить (unpin), заменить все. IP whitelist ограничивает подключения только с разрешённых IP.

**Q: Видит ли пользователь чужой трафик?**
A: Нет. Каждый пользователь видит только свой трафик (получено/отправлено/всего, лимиты, TTL).

### Технические вопросы

**Q: Как работает аутентификация?**
A: Два отдельных механизма:
- Admin: cookie `sid` (HMAC-signed, Path=/, HttpOnly, SameSite=Lax, Max-Age=24ч). Логин через `/panel/login` (user + password, scrypt hash).
- User Portal: cookie `psid` (HMAC-signed с префиксом `portal:`, Path=/, HttpOnly, SameSite=Lax, Max-Age=24ч). Логин через `/portal/login` (email + portal_password) или авто-логин по UUID.

Куки изолированы — admin-сессия не даёт доступ к user-функциям, и наоборот.

**Q: Нужен ли отдельный nginx front для User Portal?**
A: Нет. User Portal работает на том же порту 9745 что и Admin Panel. nginx front `chimera-wpp-nginx` проксирует всё на backend 9744. Отдельный `nginx_front_portal` не нужен.

**Q: Что с авто-обновлением WPP?**
A: Авто-обновление отключено (`auto_update.enabled = false`). Причина: upstream `POLESNIESOVETI12/web-panel-proxy` удалён с GitHub (404). Cron остаётся установленным, но `wpp_autoupdate_cron()` сразу return'ит при `enabled=false`.

**Q: Что если upstream воскреснет?**
A: Включить авто-обновление: `state.auto_update.enabled = true`. Но: auto-update обновляет только `wpp_panel_www/` (статический кеш), а НЕ chimera-модули. Python-твики (fingerprint dropdown, VLESS URL, cascade form, User Portal, admin gap UI) — в chimera git, не затираются auto-update.

**Q: Как обновить WPP после изменений в chimera?**
A: `git pull origin chimera-v5` на сервере → `systemctl restart wpp-web`. Python-модули обновляются через git, а не через WPP auto-update.

**Q: Затрут ли мои твики при обновлении?**
A: Нет. Твики в `chimera/modules/wpp_ui.py`, `wpp_panel_web.py`, `wpp_portal.py`, `wpp_admin_extras.py` — в chimera git. WPP auto-update (даже если включён) обновляет только `wpp_panel_www/` (статический кеш), а НЕ Python-модули.

**Q: На каких серверах установлен WPP?**
A: WPP устанавливается через chimera TUI: `1 → W → 9 → Install`. На текущий момент установлен только на server 1. На server 2 и 3 WPP не установлен.

**Q: Можно ли использовать WPP без chimera?**
A: Нет. WPP в chimera интегрирован с state.json, users.json, xray config, chimera modules (subscription, satellite_bindings, backup_rollback, etc.). Standalone WPP (из upstream) — отдельный проект с другой архитектурой.

---

*Документ составлен 27 сентября 2026. Актуально для коммитов `016119f`,
`fdaf436`, `561a034`, `04e1ca8` на ветке `chimera-v5`.*
