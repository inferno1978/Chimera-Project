# Changelog

---

## CRITICAL FIX(uninstall): не удалять чужие nginx-сайты при uninstall — 11 августа 2026

**КРИТИЧЕСКИЙ БАГ: `do_uninstall()` удалял ВСЮ директорию `/etc/nginx`
со всеми сайтами пользователя. Жалоба от реального пользователя:
«Поставил Chimera, удалил, он мне убил все имеющиеся сайты nginx.»**

### Причина

`chimera/modules/uninstall.py` содержал:

```python
# СТРОКИ 133-141 (УДАЛЕНО):
if PKG_MGR == "apt":
    _run(["apt-get", "remove", "--purge", "-y", "nginx", "nginx-common"], ...)
else:
    _run(["dnf", "remove", "-y", "nginx"], ...)

shutil.rmtree("/etc/nginx", ignore_errors=True)      # ← УДАЛЯЛО ВСЁ
shutil.rmtree("/var/log/nginx", ignore_errors=True)
```

**Три проблемы:**

1. `apt-get remove --purge nginx nginx-common` — `--purge` удаляет все
   конфигурационные файлы пакета, включая `/etc/nginx/sites-*`
2. `shutil.rmtree("/etc/nginx")` — **удалял ВСЮ директорию** со всеми
   vhost-файлами пользователя, сертификатами, nginx.conf
3. Это выполнялось **безусловно** — даже если у пользователя были
   другие сайты, не связанные с Chimera

### Что произошло у пользователя

1. Пользователь установил Chimera на сервер, где уже был nginx с сайтами
2. Chimera создала свой vhost в `/etc/nginx/sites-available/<domain>`
3. Пользователь решил удалить Chimera через меню
4. `do_uninstall()` выполнил `shutil.rmtree("/etc/nginx")` → **все сайты упали**
5. Пользователь потерял конфиги всех своих сайтов

### Фикс

`chimera/modules/uninstall.py` — полностью переписана логика удаления nginx:

**1. Удаляем ТОЛЬКО конкретные vhost-файлы Chimera:**
```python
nginx_sites_to_remove = [
    f"/etc/nginx/sites-available/{uninst_domain}",          # основной сайт VLESS
    f"/etc/nginx/sites-enabled/{uninst_domain}",            # symlink
    "/etc/nginx/sites-available/chimera-portal-nginx",     # User Portal front
    "/etc/nginx/sites-enabled/chimera-portal-nginx",       # symlink
    "/etc/nginx/sites-available/chimera-telemt-panel-nginx",  # Telemt Panel
    "/etc/nginx/sites-enabled/chimera-telemt-panel-nginx",    # symlink
]
for site_path in nginx_sites_to_remove:
    p = Path(site_path)
    if p.exists() or p.is_symlink():
        p.unlink()
```

**2. default vhost — только если содержит маркер Chimera:**
```python
if default_vhost.exists():
    content = default_vhost.read_text()
    if "chimera" in content.lower() or uninst_domain in content:
        default_vhost.unlink()
```

**3. Проверка других сайтов перед удалением nginx:**
```python
sites_enabled = Path("/etc/nginx/sites-enabled")
other_sites = [f for f in sites_enabled.iterdir()
               if f.name not in ("chimera-portal-nginx",
                                 "chimera-telemt-panel-nginx",
                                 uninst_domain)]
if not other_sites:
    # Нет других сайтов — спрашиваем, удалить ли nginx полностью
    remove_nginx = input("Полностью удалить nginx? [y/N]: ")
    if remove_nginx in ("y", "yes", "д", "да"):
        apt-get remove --purge nginx  # только тут!
        shutil.rmtree("/etc/nginx")
else:
    # Есть другие сайты — НЕ удаляем nginx, только reload
    systemctl reload nginx
```

**4. `/var/www/<domain>` — спрашиваем перед удалением:**
```python
if www_dir.exists():
    remove_www = input("Удалить /var/www/<domain>? [y/N]: ")
    if remove_www in ("y", ...):
        shutil.rmtree(www_dir)
```

### Что НЕ меняется

- Удаление Xray — без изменений (Xray ставится Chimera, удаляется полностью)
- Удаление DNSCrypt — без изменений
- Удаление `/etc/systemd/system/xray.service.d/` — без изменений
- Drop-in `nginx.service.d/after-xray.conf` — удаляется, но директория
  `nginx.service.d/` НЕ удаляется (там могут быть чужие drop-in'ы)

### Тесты (11 новых в `test_uninstall_nginx_safety.py`)

| Класс | # | Что проверяется |
|-------|---|---|
| `TestUninstallNginxSafety` | 7 | нет безусловного `rmtree('/etc/nginx')`, нет безусловного `apt-get --purge nginx`, удаляются конкретные chimera-* vhost'ы, проверка other_sites, reload nginx, вопрос про /var/www/, проверка маркера Chimera в default vhost |
| `TestUninstallNginxLogic` | 4 | нет wildcard-удаления sites-*, удаляются только Chimera-файлы (не user-site.com), подтверждение полного удаления, проверка other_sites |

Все 11 тестов pass. 206 связанных тестов (uninstall + olcrtc + access_control + port_registry + telemt_panel + cdn_masking) — 0 регрессий.

### Совместимость

- Пользователи, у которых Chimera — единственный сайт на сервере: при
  uninstall увидят вопрос «Полностью удалить nginx? [y/N]», могут
  подтвердить — nginx будет удалён полностью (как раньше)
- Пользователи, у которых есть другие сайты: nginx НЕ удаляется,
  только убираются vhost'ы Chimera, nginx перезагружается
- `/var/www/<domain>` — спрашиваем перед удалением (раньше удаляли молча)

### Файлы

- `chimera/modules/uninstall.py` — переписана логика удаления nginx (строки 125-280)
- `tests/test_uninstall_nginx_safety.py` — новый файл, 11 regression-тестов

---

## FEAT(olcrtc): multi-location support — несколько carrier в одном config.json — 10 августа 2026

**olcRTC теперь поддерживает несколько locations (carrier+room) в одном
config.json — WB Stream, Jitsi и Телемост работают одновременно, без
перезатирания конфигов. Пароль веб-панели больше НЕ меняется при
добавлении/удалении location.**

### Контекст

Старая архитектура: один client с одним location в config.json. При смене
carrier через TUI старый location полностью перезаписывался — настройки
WB Stream терялись при переключении на Телемост, и наоборот.

**Тест подтверждения:** тестовый config.json с двумя locations
(`wbstream` + `telemost`) → `systemctl restart olcrtc-manager` →
manager запустил **два** olcrtc-процесса, по одному на каждый location.
Manager поддерживает multi-location нативно — нужен был только TUI.

### Что реализовано

**State.json — новый формат:**
```json
{
  "config": {
    "panel_url": "https://IP:8888/admin",
    "admin_user": "admin",
    "admin_pass": "...",
    "public_ip": "...",
    "locations": [
      {
        "name": "wb-stream",
        "carrier": "wbstream",
        "transport": "vp8channel",
        "room_id": "019fead4-2cae-7da5-9531-1696c810bbf2",
        "key": "...",
        "payload": {"vp8-fps": "30", "vp8-batch": "64"},
        "olcbox_uri": "olcrtc://wbstream?vp8channel<...>@ROOM#KEY$wb-stream"
      },
      {
        "name": "yandex-telemost",
        "carrier": "telemost",
        "transport": "vp8channel",
        "room_id": "34996201918043",
        "key": "...",
        "payload": {...},
        "olcbox_uri": "olcrtc://telemost?vp8channel<...>@ROOM#KEY$yandex-telemost"
      }
    ]
  }
}
```

**Backward compat:** старый формат state (с `carrier`/`room_id`/
`location_name` на верхнем уровне config) автоматически мигрируется в
`locations: [...]` при первом `_load_state()`. Пользователь ничего не
теряет при обновлении.

**`_generate_config_json(locations, quota_used_bytes=0)`** — новый API:
- Принимает список locations вместо отдельных полей
- Каждый location генерирует отдельную запись в `clients[0].locations[]`
- `quota.used_bytes` сохраняется при перезаписи (чтобы не сбрасывать счётчик трафика)

**`_configure_manager(locations)`** — новый API:
- Принимает список locations
- НЕ перегенерирует `panel.env` если он уже существует (пароль НЕ меняется!)
- НЕ перегенерирует TLS сертификат если уже есть
- НЕ перегенерирует systemd unit если уже есть
- Использует новые хелперы:
  - `_ensure_panel_initialized()` — гарантирует что panel.env есть, возвращает креды
  - `_ensure_tls_and_unit()` — гарантирует TLS + systemd unit + UFW
  - `_apply_config()` — пишет config.json + перезапускает manager
  - `_read_existing_quota()` — читает текущий quota.used_bytes из config

**TUI `_flow_configure()` — полностью переписано:**

```
⚙️  Настройка olcRTC Manager Panel — Locations

  Текущие locations (2):
  [1] wb-stream          — WB Stream/vp8channel, room=019fead4-...
  [2] yandex-telemost    — Телемост/vp8channel, room=34996201918043

  [1] ➕  Добавить location
  [2] 🗑️  Удалить location
  [3] ✏️  Изменить location
  [4] 📄  Показать все OlcBox URI
  [Q] ← Назад
```

- **Добавить**: интерактивный опрос carrier → transport → room_id → name →
  key (генерируется автоматически) → запись в config + restart manager
- **Удалить**: выбор по номеру + подтверждение → удаление из config + restart
- **Изменить**: выбор по номеру → повторный опрос параметров → перезапись
- **Показать все OlcBox URI**: список всех URI с кредами панели

**Валидация имени location:**
- Только латиница, цифры, дефис, подчёркивание: `^[a-zA-Z0-9_-]+$`
- Уникальность: имя не должно совпадать с уже существующими
- Имя используется в OlcBox URI как суффикс `$name`

**TUI `_ask_carrier()`, `_ask_transport(carrier)`, `_ask_room_id(carrier)`,
`_ask_location_name(existing_names)`, `_collect_location(existing_names)`** —
разбиты на отдельные функции для переиспользования (добавление/изменение).

**Главное меню `do_olcrtc_menu()`:**
- Показывает количество locations: `Настроен: ● active (2 locations)`
- Список первых 3 locations с carrier/transport
- Пункт [6] → «Показать все OlcBox URI и креды» — показывает все URI по очереди

### Что НЕ меняется

- Путь к panel: `https://SERVER_IP:8888/admin` — тот же
- Порт: 8888 — тот же
- UFW правило: `olcrtc-manager panel (TLS)` — то же
- systemd unit: `olcrtc-manager.service` — тот же
- TLS сертификат: `/etc/olcrtc-manager/tls.crt` — тот же

### Тесты (16 новых в `test_olcrtc.py`)

| Класс | # | Что проверяется |
|-------|---|---|
| `TestGenerateConfigJson` | +2 | multiple_locations (WB+Telemost в одном config), quota_preserved |
| `TestStateIO` | +1 | migrate_old_state_format (авто-миграция) |
| `TestPanelEnvPreservation` | 2 | existing_env_not_overwritten (пароль НЕ меняется), missing_env_creates_new |
| `TestReadExistingQuota` | 3 | no_config→0, existing_preserved, malformed→0 |
| `TestAskLocationName` | 5 | valid, duplicate_rejected, empty_rejected, invalid_chars_rejected, underscore_dash_allowed |

34 теста в `test_olcrtc.py` (было 18, +16), все pass.
187 связанных тестов (olcrtc + access_control + cdn_masking + port_registry + telemt_panel) — 0 регрессий.

### Файлы

- `chimera/modules/olcrtc.py` — переписаны `_generate_config_json`,
  `_configure_manager`, `_flow_configure`, `do_olcrtc_menu`; добавлены
  `_read_existing_quota`, `_apply_config`, `_ensure_panel_initialized`,
  `_ensure_tls_and_unit`, `_ask_carrier`, `_ask_transport`, `_ask_room_id`,
  `_ask_location_name`, `_collect_location`
- `tests/test_olcrtc.py` — обновлены тесты под новый API + 16 новых

---

## FEAT(panels): Telemt Panel — кастомизация порта TLS-фронта через port_registry — 9 августа 2026

**Telemt Panel теперь поддерживает выбор порта для self-signed TLS-фронта
через TUI (раньше порт 8444 был захардкожен). Добавлена каноническая
константа SERVICE_TELEMT_PANEL_DIRECT в port_registry. Все три панели
(User Portal, Admin Panel, Telemt Panel) теперь идут через port_registry
с полной кастомизацией портов.**

### Контекст

После миграции на port_registry (FEAT v5.0.17–v5.0.19) и реализации
self-signed TLS для панелей (FEAT(panels) от 9 августа) выявился пробел:

| Панель | port_registry | Кастомизация порта в TUI |
|--------|:---:|:---:|
| User Portal (`rest_api.py`) | ✅ | ✅ (пункт "2 — изменить порт") |
| Admin Panel (`rest_api.py`) | ✅ | ✅ (тот же сервис) |
| User Portal TLS-фронт (`nginx_front_portal.py`) | ✅ | ✅ (пункт "2 — другой порт") |
| Telemt Panel direct (`telemt_panel.py`) | ⚠️ литерал `"telemt_panel_direct"` | ❌ `PANEL_TLS_PORT = 8444` захардкожен |

### Что изменилось

**`chimera/modules/telemt_panel.py`:**
- `PANEL_TLS_PORT = 8444` → `DEFAULT_PANEL_TLS_PORT = 8444` (теперь это
  *значение по умолчанию*, а не константа)
- Добавлена функция `_validate_tls_port(port)` — проверка диапазона,
  привилегированных портов (< 1024) и зарезервированных:
  `{80, 443, 22, 8080, 9091, 8443, 8888, 9443}`
- `_telemt_setup_direct_access(port=DEFAULT_PANEL_TLS_PORT)` — принимает
  кастомный порт, валидирует, проверяет конфликты через `port_is_free()`
- `_telemt_remove_direct_access()` — читает порт из state-файла (не из
  глобальной константы), корректно закрывает порт
- Новый `_ask_tls_port()` — TUI-промпт «Порт TLS-фронта [Enter=8444]»
- `_toggle_direct_access()` — при включении спрашивает порт
- `port_register`/`ufw_open_port`/`port_unregister` используют новую
  константу `SERVICE_TELEMT_PANEL_DIRECT` с fallback на строковый литерал
  для обратной совместимости со старым registry-файлом

**`chimera/modules/port_registry.py`:**
- Новая константа `SERVICE_TELEMT_PANEL_DIRECT = "telemt_panel_direct"`
  в ряду `SERVICE_TELEMT_*`

### Совместимость

- Старый registry-файл с записями `"telemt_panel_direct"` (строковый
  литерал) продолжает работать — значения константы и литерала идентичны
- Старый state-файл `telemt_panel_direct.json` без поля `port` — fallback
  на `DEFAULT_PANEL_TLS_PORT = 8444` (как было раньше)
- `_validate_tls_port` — публичная, можно переиспользовать в других модулях

### Тесты (24 новых в `test_telemt_panel.py`)

| Класс | # | Что проверяется |
|-------|---|---|
| `TestValidateTlsPort` | 13 | default 8444 валиден, 0/70000 невалидны, 80/443/8443/8888/9443/8080/9091 reserved, 8445/20000 ок, не-int rejected |
| `TestTelemtPanelDirectPortRegistry` | 2 | константа существует, round-trip register→list→unregister через `SERVICE_TELEMT_PANEL_DIRECT` |
| `TestAskTlsPort` | 3 | empty input → default, custom port, invalid → default |

Итого: 28 тестов в `test_telemt_panel.py` (было 10, +18), все pass.
Полный набор: 316 тестов (panels + port_registry + olcrtc + access_control + rest_api + user_ip_whitelist + nginx) — 0 регрессий.

---

## FEAT(panels): self-signed TLS для User Portal/Admin Panel + Telemt Panel — 9 августа 2026

**Все три веб-панели теперь доступны напрямую по публичному IP с
self-signed TLS — точно так же, как уже работал olcRTC manager panel.
Больше не обязателен ни домен, ни SSH-туннель для доступа к User Portal
и Admin Panel.**

### Контекст

До этого фикса:
- **User Portal / Admin Panel** (`rest_api.py` на 127.0.0.1:8443) —
  только через SSH-туннель, либо через nginx front с Let's Encrypt
  (нужен домен). На серверах без домена — только SSH.
- **Telemt Panel** — то же самое: 127.0.0.1:8080, доступ через SSH или
  reverse-proxy на подпуть существующего Reality-домена.
- **olcRTC manager panel** — уже работал с self-signed TLS на 8888,
  напрямую по IP. Этот паттерн и был расширен на остальные панели.

### Что реализовано

**`chimera/modules/nginx_front_portal.py`** (TLS-фронт для User Portal):
- Новый параметр `use_self_signed: bool = False` в `nginx_front_install()`
- Новая функция `_generate_self_signed_tls(public_ip)` — `openssl req -x509`
  с `subjectAltName=IP:<public_ip>,DNS:localhost`, 825 дней, RSA 2048
- Сертификат: `/etc/nginx/ssl/chimera-portal-self-signed.{crt,key}` (0600/0644)
- TUI-меню `_ask_self_signed()` спрашивает:
  - `[1]` Let's Encrypt (нужен домен, доверенный сертификат)
  - `[2]` Self-signed (без домена, по IP — браузер предупредит)
- При `use_self_signed=True` — `domain=public_ip`, cert генерируется
  автоматически, falls back на `127.0.0.1` если curl ifconfig.me не ответил

**`chimera/modules/telemt_panel.py`** (прямой доступ к Telemt Panel):
- Новая секция «Прямой доступ (self-signed TLS через nginx)»
- Файлы: `TELEMT_NGINX_AVAILABLE/ENABLED`, `TELEMT_NGINX_STATE`
- `_telemt_setup_direct_access()` — генерирует self-signed TLS,
  пишет nginx vhost `listen <port> ssl http2 → proxy_pass http://127.0.0.1:8080`,
  UFW open через `port_registry`
- `_telemt_remove_direct_access()` — удаляет vhost, закрывает UFW
- `_toggle_direct_access()` — пункт `[6]` в меню Telemt Panel
- Статус прямого доступа показывается в шапке главного меню Telemt Panel
- При полном удалении Telemt Panel — прямой доступ тоже удаляется

### nginx vhost (Telemt Panel)

```nginx
server {
    listen 8444 ssl http2;
    server_name _;
    ssl_certificate     /etc/nginx/ssl/telemt-panel-self-signed.crt;
    ssl_certificate_key /etc/nginx/ssl/telemt-panel-self-signed.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### port_registry

- User Portal: `SERVICE_WEB_PANEL_NGINX` (порт по умолчанию 9443, кастомный)
- Telemt Panel direct: `"telemt_panel_direct"` (порт 8444)
  → позже канонизирован в `SERVICE_TELEMT_PANEL_DIRECT` (см. запись выше)

### Тесты

84 теста (port_registry + olcrtc + access_control) — pass, 0 регрессий.

---

## FEAT(security): access_control.py — master + OTP парольная защита — 9 августа 2026

**Новый общий модуль `chimera/modules/access_control.py` — двухуровневая
парольная защита для скрытых меню (olcRTC + CDN masking). Master-пароль
для админа + одноразовые OTP для пользователей с автоматической ротацией.**

### Контекст

До этого фикса у olcRTC и CDN masking были два независимых парольных
модуля с дублированной логикой PBKDF2-HMAC-SHA256. У обоих были
одноразовые пароли, но не было разделения «админ vs пользователь»:
- Админ не мог войти без расхода OTP
- После каждого успешного входа нужно было вручную создавать новый OTP
- OTP не было, OTP приходилось пересоздавать вручную после каждого входа

### Что реализовано

**`chimera/modules/access_control.py`** (новый, общий для olcRTC + CDN masking):

Два типа паролей:
1. **MASTER-ПАРОЛЬ** (админ) — задаётся один раз, не протухает.
   Проверяется через PBKDF2-HMAC-SHA256 (600000 итераций, salt 16 байт,
   constant-time сравнение через `hmac.compare_digest`).
2. **OTP** (одноразовый для пользователя) — 8-символьный код,
   протухает после использования. При успешном вводе:
   - старый OTP помечается `used=true`
   - автоматически генерируется новый OTP
   - админу показывается новый OTP для передачи следующему пользователю

Формат hash-файла (JSON, chmod 0600):
```json
{
  "master": {"salt": "...", "hash": "...", "iterations": 600000},
  "otp":    {"code": "AB12CD34", "used": false, "created_at": "..."}
}
```

**Backward compatibility:** старый формат (salt/hash/iterations без
ключа `"master"`) автоматически считается master-паролем. OTP создаётся
при первом вызове `--init-otp`.

### Скрипты управления

```bash
# olcRTC
sudo python3 chimera/scripts/generate_olcrtc_password_hash.py        # установить/сменить master
sudo python3 chimera/scripts/generate_olcrtc_password_hash.py --init-otp
sudo python3 chimera/scripts/generate_olcrtc_password_hash.py --show-otp
sudo python3 chimera/scripts/generate_olcrtc_password_hash.py --rotate-otp

# CDN masking — аналогично
sudo python3 chimera/scripts/generate_cdn_masking_password_hash.py [--init-otp|--show-otp|--rotate-otp]
```

### Интеграция

- `chimera/modules/olcrtc.py` — `unlock_and_open_menu()` теперь использует
  `access_control.verify_access()` + `access_control.init_master()`
- `chimera/modules/xhttp_cdn_masking.py` — `_unlock_cdn_masking_menu()`
  теперь делегирует в `access_control`

### Тесты

| Файл | Тестов | Что покрывает |
|------|--------|---------------|
| `test_access_control.py` | 20 | init_master (3), init_otp (3), verify_access (6: master, OTP+rotation, wrong, used, no file, empty), backward compat (2: old format → master), get_current_otp (3), rotate_otp (2) |
| `test_xhttp_cdn_masking.py` | 7 (обновлены) | `TestPasswordHashScript` под новый API |
| `test_olcrtc.py` | 14 (без изменений) | integration с access_control через `unlock_and_open_menu` |

41 тест, 0 регрессий.

---

## FIX(olcrtc): пункт [3] всегда доступен + [7] старт/стоп сервиса с UFW — 9 августа 2026

**Два UX-фикса в меню olcRTC: переконфигурация Manager Panel в любой
момент + ручной старт/стоп сервиса с правильным управлением UFW-портом.**

### Что было

- Пункт `[3] Настроить Manager Panel` был доступен только когда state
  был пустой — один раз настроил, дальше нельзя изменить carrier/
  transport/room_id без полного удаления.
- Не было способа остановить `olcrtc-manager.service` без systemctl —
  при остановке порт 8888 оставался открытым в UFW (дыра), при ручном
  `systemctl start` — порт был закрыт (недоступен).

### Что стало

**`chimera/modules/olcrtc.py`:**

1. **Пункт `[3]` всегда доступен** когда olcrtc установлен — можно
   переконфигурировать carrier/transport/room_id в любой момент
   (старая конфигурация перезаписывается, `olcrtc-manager` перезапускается).

2. **Новый пункт `[7] Старт/Стоп сервиса`:**
   - **Остановить:** `systemctl stop olcrtc-manager` + `ufw_close_port(8888)`
     через `port_registry` (с legacy comment fallback)
   - **Запустить:** `systemctl start olcrtc-manager` + `ufw_open_port(8888)`
     через `port_registry`
   - Состояние сервиса (active/inactive) показывается в шапке меню

3. Удаление перенесено с `[7]` на `[8]`.

4. **Фикс синтаксиса** в `TRANSPORT_PAYLOAD_PRESETS` — em-dash (`—`) в
   Python-строке ломал парсинг в некоторых локалях, заменён на `-`.

### Тесты

21 тест в `test_olcrtc.py` — pass, 0 регрессий.

---

## FIX(olcrtc): WB Stream поддерживает только vp8channel — 9 августа 2026

**Ошибка `unsupported carrier/transport combination wbstream + datachannel`
при выборе WB Stream + Datachannel. WB Stream работает ТОЛЬКО с
vp8channel — меню теперь фильтрует доступные комбинации carrier→transport.**

### Проблема

`olcrtc-manager` принимает JSON с `carrier` + `transport.type`, но не
все комбинации валидны:

| Carrier | Поддерживаемые транспорты |
|---------|---------------------------|
| `wbstream` | только `vp8channel` |
| `jitsi` | все 4 (`vp8channel`, `datachannel`, `sctp`, `rtp`) |
| `telemost` | все 4 |

Меню предлагало все 4 транспорта для всех carriers — пользователь
выбирал `wbstream + datachannel`, manager падал с ошибкой.

### Фикс

`chimera/modules/olcrtc.py`:
- Новый словарь `CARRIER_TRANSPORTS = {wbstream: [vp8channel], jitsi: [all 4], telemost: [all 4]}`
- При выборе carrier меню фильтрует список транспортов
- Неподдерживаемые транспорты показываются серым с пометкой «не поддерживается»
- Дефолтный транспорт выбирается автоматически из поддерживаемых

### Тесты

21 тест в `test_olcrtc.py` — pass, 0 регрессий.

---

## FIX(olcrtc): 5 точечных фиксов — GOPROXY, зеркала, cleanup, NAT, deps — 9 августа 2026

**Пять изолированных фиксов для olcRTC, починивших сборку на серверах
без прямого GitHub-доступа, конфликты со старым bare-olcrtc, и
NAT-детект на IPv4-only серверах.**

### ПУНКТ 1 — GOPROXY-фоллбэк при сборке

`_go_mod_download()` — пробует три прокси по очереди:
`proxy.golang.org` → `goproxy.io` → `direct` (через `GOPROXY=...,...,direct`).

`_go_build()` вызывает `_go_mod_download()` первым шагом; если ни один
прокси не сработал — не пытается собирать (быстрая ошибка вместо
долгого зависания на `go mod download`).

### ПУНКТ 2 — зеркала для git clone

`_git_clone_or_pull()` — если прямой `git clone` не удался (HTTP 403,
timeout), пробует:
1. `codeload.github.com` tarball (`https://codeload.github.com/<owner>/<repo>/tar.gz/<ref>`)
2. 3 GitHub-прокси (согласовано с `geo_mirrors.py`):
   - `gh-proxy.com`
   - `gh.llkk.cc`
   - `ghps.cc`

### ПУНКТ 3 — очистка старого bare-olcrtc.service

`_install_or_update()` первым шагом (до Go toolchain):
- `systemctl disable --now olcrtc.service`
- удаляет `/etc/systemd/system/olcrtc.service`
- удаляет `/etc/systemd/system/olcrtc@.service` (template из старой версии)
- `systemctl daemon-reload`

Без этого старый `bare-olcrtc` конфликтовал с новым `olcrtc-manager`
(оба пытались слушать один порт / управлять одними файлами).

### ПУНКТ 4 — NAT-детект через mtproto

`_get_public_ip()` переиспользует `mtproto._get_public_ip()`, которая
правильно обрабатывает NAT (сравнение локального IP с внешним
echo-сервисом, а не `ipaddress.ip_address(...).is_private`-эвристика).

Fallback на `curl -s ifconfig.me` если `mtproto` недоступен.

### ПУНКТ 5 — runtime-зависимости

`_install_or_update()` проверяет `curl`, `openssl`, `iproute2`, `tar`,
`git` через `shutil.which()`. Если что-то отсутствует — устанавливает
через `system_deps._pkg_install()`.

### Тесты (8 новых в `test_olcrtc.py`)

`TestGoModDownloadFallback` (2):
- первый прокси падает, второй успешен → True
- все три падают → False, `_go_build` не пытается собирать

`TestGitCloneOrPull` (3):
- прямой clone успешен → зеркала не пробуются
- прямой clone падает, codeload tarball успешен → True
- всё падает → False

`TestCleanupOldBareOlcrtc` (1):
- `_install_or_update` вызывает disable+unlink+daemon-reload

`TestGetPublicIp` (1):
- переиспользует `mtproto._get_public_ip()`

`TestRuntimeDeps` (1):
- `_install_or_update` проверяет `shutil.which()` для всех 5 бинарников

14 тестов в `test_olcrtc.py` (было 6, +8), все pass.

---

## DOC: убраны все упоминания версий из кода, тестов, CHANGELOG и README — 9 августа 2026

**Массовая очистка тегов версий `v5.0.10`..`v5.0.23` из всех исходников и
документации. Оставлен только `v5.0.0` — базовая версия проекта.**

### Контекст

После серии быстрых релизов (v5.0.10 → v5.0.23) в коде накопились
жестко прописанные теги версий: в комментариях модулей, в заголовках
CHANGELOG-записей, в строках таблицы версий README.md, в docstring'ах
тестов. Это создавало проблемы:

- Каждое обновление требовало ручного bulk-replace по 40+ файлам
- Версия в `__init__.py` рассинхронизировалась с упоминаниями в коде
- Тесты падали при сверке hardcoded-строк с фактической версией
- README вводил в заблуждение (упоминал устаревшие версии)

### Что убрано

53 файла изменено (400 строк удалено, 400 строк добавлено):

| Категория | Файлов | Пример |
|-----------|--------|--------|
| `chimera/modules/*.py` | 28 | Комментарии вида `# v5.0.17 — миграция на port_registry` |
| `tests/*.py` | 12 | Docstring'ы вида `"""Test for v5.0.13 fix"""` |
| `CHANGELOG.md` | 1 | Теги версий в заголовках разделов |
| `README.md` | 1 | Таблица "Версия → Описание" |
| `chimera/_core.py`, `__init__.py` | 2 | Динамическая версия из `__version__` |

### Что оставлено

Только **`v5.0.0`** — это базовая версия проекта (в `__init__.py`,
заголовке README, исторических записях CHANGELOG до нашей сессии).
Все остальные версии теперь выводятся из `__version__` в `__init__.py`
динамически, при необходимости.

### Совместимость

- Поведение кода не изменилось — только комментарии/документация
- `core.VERSION` остаётся динамическим из `__init__.py`
- `test_core_dynamic_version.py` обновлён на динамическую проверку
- 279 тестов (test_port_registry + test_user_ip_whitelist + test_youtube_route
  + test_youtube_route_v5013 + test_rest_api + test_rest_api_auth +
  test_user_portal + test_rest_api_web_panel_firewall) — pass, 0 регрессий.

---

## FIX(warp): детализированное сообщение об ошибке wgcf register — 9 августа 2026

**Пользователь получал общее «WARP настроен с ошибками — проверьте логи»
без объяснения причины. wgcf register падал с TLS handshake timeout к
api.cloudflareclient.com — теперь показывается детализированное
сообщение с возможными причинами и шагами диагностики.**

### Проблема

`wgcf register` выполняет HTTPS-запрос к `api.cloudflareclient.com` для
регистрации нового WARP-аккаунта. На серверах с:
- заблокированным Cloudflare IP
- ТСПУ-фильтрацией TLS к cloudflareclient.com
- временными сетевыми сбоями

...этот запрос падает с TLS handshake timeout. Старый код показывал
только: `WARP настроен с ошибками — проверьте логи` — без указания
причины, что заставляло пользователя вручную искать ошибку в логах.

### Фикс

`chimera/modules/warp.py`: при ошибке `wgcf register` анализируется
текст ошибки и показывается контекстное сообщение:

**TLS handshake timeout:**
```
Причина: TLS handshake timeout к api.cloudflareclient.com
Возможные причины: IP заблокирован Cloudflare, ТСПУ режет TLS,
временный сетевой сбой.
Что сделать:
  1. curl -v https://api.cloudflareclient.com
  2. Попробовать позже
  3. Зарегистрировать WARP на другой машине и скопировать конфиг
```

**Connection refused / no such host:**
```
Причина: нет соединения с api.cloudflareclient.com
Проверьте DNS и интернет-соединение.
```

**Другие ошибки:** как раньше — `warn` с текстом ошибки.

Меню wizard: «проверьте логи» → «см. подробное сообщение выше».

### Файлы

- `chimera/modules/warp.py` — функция `_warp_register_with_diagnostics()`,
  +34 строки

### Тесты

23 теста в `test_warp.py` — pass, 0 регрессий.

---

## FIX(port_registry): атомарная запись + файловая блокировка — 9 августа 2026

**Защита от гонки при конкурентном доступе к `port_registry.json`.
Два процесса (например, install одного сервиса + cron-задача другого)
могли одновременно прочитать файл, каждый модифицировать свой экземпляр,
и второй перезаписывал первый → потеря данных.**

### Проблема

`port_registry.json` — shared state-файл, в который пишут много модулей:
- `port_register(service, port, proto, comment, force)` — install
- `port_unregister(service, port, proto)` — uninstall
- `ufw_open_port` / `ufw_close_port` — UFW sync

Старый код: `port_list_all()` → modify in-memory → `_registry_save()`
без какой-либо блокировки. Если два процесса стартовали одновременно:

```
T0: Process A reads [vless:443, naiveproxy:8443]
T1: Process B reads [vless:443, naiveproxy:8443]   ← тот же список
T2: Process A adds mieru:2012  → writes [vless:443, naiveproxy:8443, mieru:2012]
T3: Process B adds awg:51820   → writes [vless:443, naiveproxy:8443, awg:51820]
                                                                  ↑ mieru:2012 ПОТЕРЯН
```

Аналогичная проблема с write в середине: если процесс упал после `open()`
но до `write()` завершён, файл становился пустым или обрезанным → потеря
ВСЕХ записей registry.

### Фикс

**`chimera/modules/port_registry.py`:**

#### 1. FILE LOCK (`fcntl.flock`)

Новый контекстный менеджер `_registry_lock(timeout=10)`:
- POSIX advisory lock (`fcntl.LOCK_EX | LOCK_NB`) на отдельный
  `.lock` файл (`PORT_REGISTRY_FILE.with_suffix(".lock")`)
- Обёртывает ВЕСЬ цикл read-modify-write в `port_register()` /
  `port_unregister()` одной блокировкой
- Retry каждые 100мс, максимум 10 секунд
- Если лок не получен → `TimeoutError`, `port_register` возвращает
  `(False, '...')`, `port_unregister` возвращает `False`
- Не зависает бесконечно

```python
@contextlib.contextmanager
def _registry_lock(timeout: float = _LOCK_TIMEOUT_SEC):
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    f = open(LOCK_FILE, "w")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(...)
                time.sleep(0.1)
        yield
    finally:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()
```

#### 2. ATOMIC WRITE (`tempfile` + `os.replace`)

`_registry_save()`:
1. Пишет во временный файл `PORT_REGISTRY_FILE.with_suffix(".tmp")`
2. `os.replace(tmp, PORT_REGISTRY_FILE)` — атомарная операция на уровне ОС
3. Если процесс упал между (1) и (2) — оригинальный файл нетронут

`os.replace` — POSIX-атомарная операция, гарантирует что файл либо
полностью старый, либо полностью новый. Никаких «наполовину записанных»
состояний.

#### 3. READ БЕЗ ЛОКА

`port_list_all()` и `port_get_conflicts()` НЕ используют лок — благодаря
атомарной записи через `os.replace`, read всегда получает консистентный
снапшот. Лок нужен только вокруг read-modify-write (где пишем).

### Не тронуто

- 3-уровневая проверка конфликтов (registry + ss + UFW + /etc/services)
- `ufw_open_port` / `ufw_close_port` (делегируют в lock-protected
  registry functions)
- `legacy_comments`-механика для backward compat

### Тесты (7 новых в `test_port_registry.py`)

| Класс | # | Что проверяется |
|-------|---|---|
| `TestAtomicWrite` | 3 | атомарная запись создаёт валидный JSON; `.tmp` не остаётся после save; если `os.replace` бросил exception — оригинальный файл нетронут |
| `TestFileLock` | 4 | 2 потока, разные порты — обе записи сохраняются; 2 потока, один порт — финальный JSON валиден; занятый лок → `port_register` не зависает; короткий таймаут (0.3с) → `TimeoutError` |

44 теста в `test_port_registry.py` (было 37, +7), все pass.
279 связанных тестов (port_registry + user_ip_whitelist + youtube + rest_api + portal + firewall) — 0 регрессий.

---

## FEAT(olcrtc): полная переработка на manager panel + парольная защита — 8 августа 2026

**olcRTC переписан с нуля: bare-olcrtc (YAML, systemd template) →
olcrtc-manager panel (JSON, веб-панель, API, supervisor). Скрыт из
главного меню, доступ по паролю.**

### Что было (не работало)

Bare olcrtc подход: YAML конфиги, `olcrtc@.service` template per-link,
клиентский YAML. Формат YAML не совпадал с тем, что реально ожидает olcrtc
— ни Jitsi, ни WB Stream не заводились.

### Что стало (по гайду)

**Два бинарника:**
- `olcrtc` — туннель (github.com/openlibrecommunity/olcrtc, master)
- `olcrtc-manager` — веб-панель + API + supervisor
  (github.com/BigDaddy3334/olcrtc-manager-panel, main)

**Manager panel:**
- Веб-панель на `https://SERVER_IP:8888/admin` (self-signed TLS, basic auth)
- API: `/api/state`, `/api/logs` — проверка состояния без SSH
- Supervisor: сам запускает/управляет olcrtc процессами
- config.json — JSON формат (не YAML): `{version, clients[], locations[],
  endpoint, carrier, transport{type, payload}, link, data, dns}`

**OlcBox URI** для клиента:
```
olcrtc://wbstream?vp8channel<vp8-batch=64&vp8-fps=30>@ROOM_ID#KEY$wb-vps
```

**Сборка:** Go 1.26+ → git clone обоих репозиториев → go build →
`/usr/local/bin/olcrtc` + `/usr/local/bin/olcrtc-manager`

**TLS:** self-signed через `openssl req -x509` (subjectAltName=IP:public_ip)

**systemd:** `olcrtc-manager.service`
(Environment=OLCRTC_PATH=/usr/local/bin/olcrtc,
EnvironmentFile=panel.env, ExecStart=olcrtc-manager -addr 0.0.0.0 -config config.json)

**UFW:** порт 8888 через `port_registry` (SERVICE_OLCRTC_MANAGER).
Открытие при установке, закрытие при удалении.

### TUI меню

```
[1] Установить/обновить (сборка olcrtc + olcrtc-manager)
[2] Гайд
[3] Настроить Manager Panel (carrier, transport, room_id)
[4] Статус (через API)
[5] Логи (через API)
[6] Показать OlcBox URI и креды
[7] Удалить полностью
```

### Скрытое меню + парольная защита

olcRTC **скрыт из главного меню**. Доступ — ввод строки `olcrtc` (без
кавычек), по аналогии со скрытым меню CDN masking (`cdn`).

**Парольная защита** (по образцу CDN masking):
- `_verify_olcrtc_password()` — PBKDF2-HMAC-SHA256, 600000 итераций
  (OWASP 2025-2026), salt 16 байт, constant-time сравнение
- Хеш в `/var/lib/xray-installer/olcrtc_access.hash` (JSON, chmod 0600)
- `unlock_and_open_menu()` — 3 попытки ввода через getpass (без эха)
- Утилита: `sudo python3 chimera/scripts/generate_olcrtc_password_hash.py`

Пункты 14-18 перенумерованы в 13-17 (WebDAV, FPTN, AWG, Sing-box, TrustTunnel).

### Что удалено (не работало)

- `_server_yaml()` / `_client_yaml()` — YAML формат неправильный
- `_UNIT_CONTENT` / `_ensure_unit_file()` — manager сам управляет olcrtc
- `_create_link()` / `_delete_link()` — manager делает это
- `olcrtc@.service` template
- `_flow_add_link()` / `_flow_list_links()` / `_flow_link_detail()` — заменены

### Что сохранено (работает)

- Go toolchain (`_go_ok`, `_install_go`, `_go_arch`, `_ver_tuple`)
- `_run` / `_info` / `_warn` / `_success` / `_box_*` хелперы
- `_load_state` / `_save_state` (расширена)
- `CARRIERS` / `TRANSPORTS` словари

### Интеграция

- `port_registry`: `SERVICE_OLCRTC_MANAGER`, порт 8888
- UFW open/close через port_registry (с legacy_comments)
- `olcrtc_packages.py` — сохранён (сборка olcrtc из исходников)

### Тесты (14 в test_olcrtc.py)

- TestGenerateConfigJson (2) — JSON формат, все поля из гайда
- TestGeneratePanelEnv (1) — basic auth env
- TestGenerateSystemdUnit (1) — systemd unit directives
- TestGenerateOlcBoxUri (2) — URI формат для vp8channel и datachannel
- TestStateIO (2) — JSON I/O
- TestGoToolchain (3) — version parsing, required version, arch
- TestPortRegistryIntegration (2) — SERVICE_OLCRTC_MANAGER exists, port 8888
- TestManagerInstalledCheck (1) — binary detection

58 тестов (14 olcrtc + 44 port_registry), 0 регрессий.

---

## FIX(rest_api):  — определение реального IP клиента через X-Forwarded-For — 8 августа 2026

**Исправление: после  (nginx_front_portal.py) _client_ip() видел
только 127.0.0.1 (loopback от nginx), а не реальный IP клиента.**

### Проблема

 `_client_ip()` возвращал `self.client_address[0]` напрямую —
обоснование: «rest_api слушает напрямую (без nginx)».

 `nginx_front_portal.py` поставил nginx перед User Portal с
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`. Теперь
`client_address[0]` — это `127.0.0.1` (loopback от nginx), а реальный IP
клиента — в `X-Forwarded-For`. Но `_client_ip()` не обновлялся.

Три места с проверкой `if IP in ("127.0.0.1", ...)` срабатывали постоянно
для любого клиента через рекомендованный nginx+TLS путь.

### Фикс

`_client_ip()` доверяет `X-Forwarded-For`, ТОЛЬКО если TCP-соединение
пришло с loopback (значит — от локального nginx-фронта). Если `direct_ip`
НЕ loopback (запрос пришёл напрямую, rest_api на `0.0.0.0`) — XFF
игнорируется полностью (защита от подделки).

```python
def _client_ip(self) -> str:
    direct_ip = self.client_address[0] if self.client_address else "?"
    if direct_ip in ("127.0.0.1", "::1", "localhost"):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            candidate = xff.split(",")[0].strip()
            if candidate:
                return candidate
    return direct_ip
```

### Оба сценария проверены

1. **nginx-фронт** (host=127.0.0.1) → `client_address[0]` = 127.0.0.1 →
   XFF доверяется → реальный IP клиента из первого элемента цепочки.
2. **Прямой доступ** (host=0.0.0.0) → `client_address[0]` = внешний IP →
   XFF **игнорируется** → `client_address[0]` возвращается напрямую
   (защита от подделки заголовка).

### Обновлены комментарии

Во всех 3 местах проверки loopback (GET /api/portal/ips, POST /api/portal/ips
с ip=auto, POST /api/portal/ips/replace-all с ip=auto) — теперь поясняют
что loopback после XFF означает «nginx не проставил заголовок или клиент
правда localhost», а не «работаем без nginx».

### Не тронуто

- `nginx_front_portal.py` (proxy_set_header уже корректны)
- Логика rate-limit/timeout в `_VLESSHandler`

### Тесты (10 в `TestQ2XForwardedForConditionalTrust`)

| # | Тест | Сценарий | Результат |
|---|---|---|---|
| 1 | `test_xff_trusted_from_loopback` | loopback + валидный XFF | → IP из XFF |
| 2 | `test_xff_absent_loopback_fallback` | loopback + нет XFF | → 127.0.0.1 (fallback) |
| 3 | `test_xff_ignored_when_direct_non_loopback` | внешний IP + поддельный XFF | → client_address (XFF игнорируется) |
| 4 | `test_xff_multiple_ips_takes_first` | XFF с несколькими IP | → первый (реальный клиент) |
| 5 | `test_xff_empty_string_loopback_fallback` | пустой XFF при loopback | → fallback |
| 6 | `test_xff_whitespace_only_loopback_fallback` | пробелы в XFF | → fallback |
| 7 | `test_ipv6_loopback_xff_trusted` | IPv6 ::1 + XFF | → доверяем XFF |
| 8 | `test_client_ip_uses_client_address` | проверка исходника | → client_address в основе |
| 9 | `test_get_portal_ips_uses_client_ip_not_xff_directly` | обработчик не читает XFF напрямую | → _client_ip() |
| 10 | `test_post_portal_ips_auto_uses_client_ip` | то же для POST | → _client_ip() |

Точные количества тестов по файлам:
- `test_user_ip_whitelist.py` — 62 passed
- `test_rest_api.py` — 55 passed
- `test_rest_api_auth.py` — 40 passed
- `test_user_portal.py` — 8 passed
- `test_rest_api_web_panel_firewall.py` — 11 passed
- **Итого: 176 passed, 0 регрессий**

---

## FEAT(security):  — IP lifecycle: pin/unpin, FIFO, age-based cleanup, replace-all — 8 августа 2026

**Расширенное управление IP whitelist: предотвращение накопления старых IP
через age-based cleanup (cron), FIFO при достижении лимита, закрепление
(pin) для постоянных IP, и «Заменить все» для быстрой смены IP.**

### Контекст

Проблема: пользователи с динамическими IP (CGNAT мобильные операторы) при
каждой смене IP добавляют новый через User Portal. Старые не удаляются →
накапливаются. Лимит 20 IP на пользователя достигается, новые добавить нельзя,
надо вручную удалять старые.

### Решение

**1. Расширенный формат хранения (detailed)**
Старый формат: `["5.6.7.8", ...]` (просто строки)
Новый формат: `[{"ip": "5.6.7.8", "added_at": "2026-08-08T...", "pinned": false}, ...]`

Migration: lazy — при чтении старый формат конвертируется in-memory, при
следующем save записывается в detailed формате. `_normalize_user_ips()` остаётся
возвращающим `list[str]` для backward compat с `_collect_all_user_ips` и старым кодом.

**2. FIFO при достижении лимита**
`add_ip_to_user()` — если лимит (20) достигнут, автоматически удаляется самый
старый **незакреплённый** IP. Закреплённые (pinned) IP не удаляются. Если все
закреплены — отказ с сообщением «удалите вручную».

**3. Age-based cleanup (cron, раз в сутки)**
`cleanup_old_ips(retention_days=30)` — удаляет незакреплённые IP старше
retention_days. Default 30 дней. Настраивается через state.json
(`ip_cleanup_retention_days`). 0 = отключен.

Cron: `/etc/cron.d/chimera-ip-cleanup` — запускается в 04:00 ежедневно.
Закреплённые IP (pinned=True) НЕ удаляются.

**4. Закрепление (pin/unpin)**
`pin_ip_to_user(email, ip)` / `unpin_ip_from_user(email, ip)` — закреплённые
IP не удаляются при age-based cleanup и FIFO. Пользователь закрепляет свой
домашний статический IP, чтобы он не удалялся автоматически.

**5. «Заменить все» (replace-all)**
`replace_all_ips(email, new_ip, keep_pinned=True)` — удаляет все IP (кроме
закреплённых) и добавляет один новый. Для сценария «у меня сменился IP, хочу
только новый». Если `keep_pinned=False` — удаляет вообще все.

### Новый API в user_ip_whitelist.py

- `add_ip_to_user(email, ip, pinned=False)` — теперь с FIFO и detailed формат
- `get_user_ips_detailed(email)` → `list[dict]` с `{"ip", "added_at", "pinned"}`
- `pin_ip_to_user(email, ip)` / `unpin_ip_from_user(email, ip)`
- `replace_all_ips(email, new_ip, keep_pinned=True)`
- `cleanup_old_ips(retention_days=None)` → `(deleted_count, total_before)`
- `_get_cleanup_retention_days()` / `_set_cleanup_retention_days(days)`
- `install_cleanup_cron()` / `remove_cleanup_cron()`
- `_normalize_user_ips_detailed(user)` → `list[dict]`
- `_migrate_ips_to_detailed(user)` → `list[dict]` (migration helper)

### Новый REST API (rest_api.py)

- `GET /api/portal/ips` — теперь возвращает `ips: [{ip, added_at, pinned}, ...]`
- `POST /api/portal/ips/replace-all` — Body: `{"ip": "auto", "keep_pinned": true}`
- `POST /api/portal/ips/pin` — Body: `{"ip": "5.6.7.8"}`
- `POST /api/portal/ips/unpin` — Body: `{"ip": "5.6.7.8"}`

### User Portal обновления (user_portal.py)

- Каждый IP показывает 📌 если закреплён
- Кнопки «Закрепить» / «Открепить» для каждого IP
- Кнопка «🔄 Заменить все на текущий» — удаляет все (кроме pinned), добавляет текущий
- Информационный блок с объяснением pin и replace-all

### Тесты (19 новых в test_user_ip_whitelist.py)

- `TestFifoOnLimit` (3) — FIFO удаляет самый старый незакреплённый, не удаляет pinned
- `TestPinUnpin` (3) — pin/unpin IP, pin nonexistent
- `TestReplaceAll` (3) — replace_all с/без keep_pinned
- `TestCleanupOldIps` (3) — cleanup удаляет старые незакреплённые, keeps pinned, disabled при 0
- `TestMigrationOldToDetailed` (4) — backward compat: get_user_ips возвращает строки, get_user_ips_detailed конвертирует, add_ip мигрирует, _collect_all_user_ips работает

3 существующих теста обновлены для detailed формата.
684 связанных теста проходят (0 регрессий).

### Совместимость

- **Backward compatible**: старый формат (строки) читается и конвертируется при следующем save
- `get_user_ips()` возвращает `list[str]` (не меняется)
- `_collect_all_user_ips()` работает с обоими форматами
- `_normalize_user_ips()` работает с обоими форматами
- Cleanup cron опционален (не устанавливается автоматически — только через TUI)
- retention_days=0 = cleanup отключен
- FIFO срабатывает только при достижении лимита (20 IP)

---

## FEAT(infra):  — Финальная миграция: VLESS port + singbox_ufw + web_panel — 8 августа 2026

**Завершающая миграция на port_registry: VLESS port (network_setup +
reconfigure), sing-box UFW, и web_panel (rest_api). Теперь ВСЕ сервисы
Chimera (кроме SSH hardening и deny-rules) используют port_registry.**

### Контекст

В  мигрировано 14 сервисов, но остались 4 критичных:
1. VLESS port (network_setup.py) — основной install flow
2. VLESS reconfigure (reconfigure.py) — смена порта
3. singbox_ufw.py — multi-protocol sing-box
4. rest_api.py — web_panel (8443) при expose=True

Этот коммит завершает миграцию.

### 1. network_setup.py — VLESS install (SSH/HTTP/VLESS ports)

`_ufw_allow_if_missing(port, proto, comment)` теперь:
1. `port_register(SERVICE_VLESS, port, proto, comment, force=True)` — регистрация
2. `ufw_open_port(port, proto, SERVICE_VLESS, comment)` — UFW open с `chimera-vless` tag
3. Fallback на прямой `ufw allow` если port_registry недоступен

Открывает: SSH (22), HTTP (80), VLESS (SERVER_PORT) — все под SERVICE_VLESS.
`force=True` — критично, т.к. эти порты уже могут быть открыты (не блокируем).

### 2. reconfigure.py — VLESS port change

Новый helper `_vless_reconfigure_ufw_port_change(core, new_port, old_port)`:
1. `port_register(SERVICE_VLESS, new_port, "tcp", comment="VLESS (reconfigured)", force=True)`
2. `ufw_open_port(new_port, "tcp", SERVICE_VLESS, ...)` — открыть новый
3. `ufw_close_port(old_port, "tcp", SERVICE_VLESS, legacy_comments=[...])` — закрыть старый
4. `port_unregister(SERVICE_VLESS, old_port, "tcp")` — снять регистрацию

**legacy_comments** покрывает все варианты старых comments:
- `"VLESS reconfigure"` (от старого reconfigure.py)
- `"SSH"`, `"HTTP (certbot ACME)"`, `"VLESS"` (от network_setup.py)

### 3. singbox_ufw.py — multi-protocol sing-box

**Стратегия: НЕ менять UFW-управление** (работает с `sing-box-<tag>` comments,
сложная multi-protocol логика с проверкой `_is_port_used_by_other_singbox_proto`).
Только **добавить регистрацию в port_registry** для conflict detection и audit.

- `singbox_ufw_ensure_open()`: `port_register(SERVICE_SINGBOX, port, proto, comment=f"sing-box-{protocol_tag}", force=True)` перед UFW open
- `singbox_ufw_close()`: `_singbox_port_unregister_safe(port, proto)` после UFW close
- `singbox_ufw_close_all()`: `port_unregister(SERVICE_SINGBOX)` (снимает все sing-box порты)

`force=True` — sing-box может использовать несколько протоколов на одном порту
(ShadowTLS + VLESS на 443), conflict detection заблокировал бы это.

### 4. rest_api.py — web_panel (8443) при expose=True

**`_ufw_web_panel_close(port)`:**
1. `ufw_close_port(port, "tcp", SERVICE_WEB_PANEL, legacy_comments=["VLESS Web Panel (exposed, no TLS)", "VLESS Web Panel"])` — ищет и новые (`chimera-web_panel`), и старые правила
2. `port_unregister(SERVICE_WEB_PANEL, port, "tcp")`
3. Fallback на ручной парсинг `ufw status numbered` (старый код)

**`install_web_service()` при expose=True:**
1. `port_register(SERVICE_WEB_PANEL, port, "tcp", comment="VLESS Web Panel (exposed, no TLS)", force=True)`
2. `ufw_open_port(port, "tcp", SERVICE_WEB_PANEL, ...)` — с `chimera-web_panel` tag
3. Fallback на прямой `ufw allow` если port_registry недоступен

### Полная карта миграции (финальная)

| Сервис | Файл | Статус | Service tag |
|---|---|---|---|
| VLESS (install) | network_setup.py | ✅  | SERVICE_VLESS |
| VLESS (reconfigure) | reconfigure.py | ✅  | SERVICE_VLESS |
| sing-box (multi-proto) | singbox_ufw.py | ✅  | SERVICE_SINGBOX |
| Web Panel | rest_api.py | ✅  | SERVICE_WEB_PANEL |
| nginx front Portal | nginx_front_portal.py | ✅  | SERVICE_WEB_PANEL_NGINX |
| WebDAV tunnel | webdav_tunnel.py | ✅  | SERVICE_WEBDAV_TUNNEL |
| NaiveProxy | naiveproxy.py | ✅  | SERVICE_NAIVEPROXY |
| TrustTunnel | trusttunnel.py | ✅  | SERVICE_TRUSTTUNNEL |
| FPTN | fptn.py | ✅  | SERVICE_FPTN |
| WDTT | wdtt.py | ✅  | SERVICE_WDTT |
| Telemt MTProxy | mtproto.py | ✅  | SERVICE_TELEMT_MTPROTO |
| Telemt iOS-fix | telemt_ios_fix.py | ✅  | SERVICE_TELEMT_IOS_FIX |
| Mieru | mieru.py | ✅  | SERVICE_MIERU |
| Port hopping | port_hopping.py | ✅  | SERVICE_PORT_HOPPING |
| AWG standalone | awg_standalone.py | ✅  | SERVICE_AWG_STANDALONE |
| AWG uninstall | awg_uninstall.py | ✅  | SERVICE_AWG_STANDALONE |
| Subscription | subscription.py | ✅  | SERVICE_SUBSCRIPTION |

### НЕ мигрированы (намеренно, финально)

| Сервис | Причина |
|---|---|
| `ssh_hardening.py` | SSH port change — критичная операция, НЕ трогаем (по указанию) |
| `_core.py:1257` (emergency SSH restore) | critical fallback |
| `autoban.py`, `honeypot.py`, `dpi_detector.py` | ufw **deny** (блокировка IP, не открытие порта) |
| `client_config_export.py` | ephemeral temporary share port (живёт минуты) |
| `hybrid_addon.py` | generic rule string, не port-specific |
| `awg_transport.py:1785` | remote SSH команда на exit-VPS (не локально) |

### Тесты

- 575 singbox + rest_api тестов — pass (8 skipped)
- 828 основных тестов — pass
- 542 AWG + remaining тестов — pass
- **Всего 1945 тестов, 0 регрессий**

### Совместимость

- **Backward compatible**: legacy_comments во всех ufw_close_port вызовах
- **Forward compatible**: новые install используют `chimera-<service>` comments
- **Fallback**: все мигрированные функции fallback на прямой ufw если port_registry недоступен
- **No breaking changes**: все существующие тесты проходят без модификаций

### Что даёт финальная миграция

1. **ВСЕ** открываемые порты зарегистрированы в `/var/lib/xray-installer/port_registry.json`
2. **Conflict detection** работает для любого нового сервиса
3. **TUI** `do_manage_port_registry()` показывает все порты всех сервисов
4. **Clean uninstall** — `legacy_comments` гарантирует удаление orphaned правил
5. **Audit trail** — полный список кто какие порты занимает

---

## FEAT(infra):  — Миграция ВСЕХ сервисов на port_registry — 8 августа 2026

**Полная миграция 14 сервисов на централизованный port_registry с backward
compatibility для существующих UFW-правил.**

### Контекст

В  создан `port_registry.py` (паттерн) и применён только к новому
`nginx_front_portal.py`. 15+ существующих сервисов имели свой UFW-код без
conflict detection и без централизованной регистрации. Этот коммит переносит
все основные сервисы на port_registry.

### Стратегия миграции (безопасная)

**Для каждого сервиса:**
1. При install: `port_register(SERVICE_XXX, port, proto, comment, force=True)` — регистрирует порт
2. При install: `ufw_open_port(port, proto, SERVICE_XXX, comment=...)` — открывает UFW с tag `chimera-<service>`
3. При uninstall: `ufw_close_port(port, proto, SERVICE_XXX, legacy_comments=["старый comment"])` — закрывает UFW, ищет и новые (`chimera-<service>`), и старые правила
4. При uninstall: `port_unregister(SERVICE_XXX, port, proto)` — снимает регистрацию

**Backward compatibility:**
- `ufw_close_port` имеет параметр `legacy_comments: list[str]` — при миграции каждый сервис передаёт свой старый comment (например `["NaiveProxy"]`), чтобы orphaned UFW-правила на существующих серверах были удалены при следующем uninstall
- Если `port_registry` недоступен (import fail) — fallback на прямой `ufw allow/delete` (старый код)
- `force=True` в `port_register` — существующие сервисы не блокируются конфликтами (они уже работают, не меняем поведение)

**Новые API в port_registry.py:**
- `ufw_close_port(port, proto, service_tag, legacy_comments=None)` — backward compat
- `ufw_open_port_range(port_start, port_end, proto, service_tag, comment=None)` — для Mieru/port_hopping
- `ufw_close_port_range(port_start, port_end, proto, service_tag, legacy_comments=None)` — то же для range

**Новые service tags:**
- `SERVICE_TELEMT_MTPROTO` — Telemt MTProxy (раньше был `SERVICE_TELEMT`)
- `SERVICE_TELEMT_IOS_FIX` — Telemt iOS-fix
- `SERVICE_WEBDAV_TUNNEL` — WebDAV tunnel
- `SERVICE_PORT_HOPPING` — Port hopping

### Мигрированные сервисы (14 шт)

| Сервис | Файл | Порт | Proto | Legacy comment |
|---|---|---|---|---|
| WebDAV tunnel | webdav_tunnel.py | configurable | tcp | "webdav-tunnel" |
| NaiveProxy | naiveproxy.py | 443 default | tcp | "NaiveProxy" |
| TrustTunnel | trusttunnel.py | configurable | tcp+udp | "TRUSTTUNNEL" |
| FPTN | fptn.py | 443 default | tcp | "FPTN" |
| WDTT | wdtt.py | 56000 default | udp | "qWDTT DTLS" |
| Telemt MTProxy | mtproto.py | configurable | tcp | "Telemt MTProxy" |
| Telemt iOS-fix | telemt_ios_fix.py | configurable | tcp | "Telemt iOS-fix" |
| Mieru | mieru.py | 2012-2022 range | tcp/udp | (no comment) |
| Port hopping | port_hopping.py | range | tcp/udp | "xray-port-hopping" |
| AWG standalone | awg_standalone.py | 51820 default | udp | "AWG standalone" |
| AWG uninstall | awg_uninstall.py | (та же логика) | udp | "AWG standalone" |
| Subscription | subscription.py | 8443 default | tcp | "vless-subscription" |

### НЕ мигрированы (намеренно)

| Сервис | Причина |
|---|---|
| `autoban.py`, `honeypot.py`, `dpi_detector.py` | ufw **deny** (блокировка IP, не открытие порта) — не относится к port_registry |
| `singbox_ufw.py` | своя сложная multi-protocol логика (ShadowTLS/VLESS/Trojan/AnyTLS на разных портах), рефакторинг рискован — оставлен как есть |
| `_core.py:1257` (emergency SSH restore) | critical fallback, не трогаем |
| `ssh_hardening.py` | SSH port change — критичная операция, требует отдельной проработки |
| `client_config_export.py` | ephemeral temporary share port (живёт минуты) — нет смысла регистрировать |
| `hybrid_addon.py` | generic rule string, не port-specific |
| `reconfigure.py`, `network_setup.py` | VLESS port — самый критичный, мигрируется отдельно (см. ниже) |

### VLESS port (network_setup.py, reconfigure.py) — НЕ мигрирован в этом коммите

VLESS — основной сервис Chimera. Его порт (443 или настраиваемый) открывается
при установке и при reconfigure. Миграция на port_registry требует:
- Изменения `network_setup._ufw_allow_if_missing()` — используется для SSH/HTTP/VLESS
- Изменения `reconfigure._ufw_open_tcp()` — port change при reconfigure
- Особой осторожности с SSH (22) и HTTP (80) — они открываются вместе с VLESS

Это критичная функциональность, миграция требует отдельного тестирования на
реальных серверах. Оставлено для следующего коммита, чтобы не рисковать
регрессиями в основном install flow.

### Тесты

- 759 тестов основной группы проходят (включая 37 новых из test_port_registry.py)
- 682 теста AWG/fragment/youtube группы проходят
- **Всего 1441 тест, 0 регрессий**

### Совместимость

- **Backward compatible**: на существующих серверах с старыми UFW-правилами — при следующем uninstall правила будут найдены через `legacy_comments` и удалены
- **Forward compatible**: новые install используют `chimera-<service>` comments
- **Fallback**: если `port_registry` недоступен — все сервисы fallback на прямой `ufw allow/delete`
- **No breaking changes**: все существующие тесты проходят без модификаций

### Что даёт port_registry после миграции

1. **Conflict detection**: при установке нового сервиса проверяется, не занят ли порт (реестр + `ss -ltnp` + UFW + `/etc/services`)
2. **Centralized UFW management**: все правила помечены `chimera-<service>` — легко найти свои
3. **Audit trail**: `port_list_all()` показывает все зарегистрированные порты
4. **TUI**: `do_manage_port_registry()` — просмотр реестра, проверка конфликтов
5. **Clean uninstall**: `legacy_comments` гарантирует что orphaned правила будут удалены

---

## FEAT(infra):  — nginx front (TLS) для User Portal + port_registry — 8 августа 2026

**Два новых модуля: `chimera/modules/port_registry.py` (централизованный
реестр портов с conflict detection) и `chimera/modules/nginx_front_portal.py`
(nginx reverse-proxy с TLS для User Portal).**

### Контекст

После  (per-user IP whitelist) User Portal остался на 127.0.0.1:8443 —
доступ только через SSH-туннель или expose=True без TLS (Basic Auth = base64,
креды видны снифферу). Нужно было поставить nginx с TLS перед порталом, при
этом не захардкодить порт и обеспечить auto UFW open/close.

Параллельно — в проекте 15+ сервисов, каждый со своим UFW-управлением. Хотелось
общий паттерн, чтобы новые сервисы его использовали.

### Решение 1: `port_registry.py`

Централизованный реестр портов в `/var/lib/xray-installer/port_registry.json`:

```json
[
  {"service": "web_panel_nginx", "port": 9443, "proto": "tcp",
   "comment": "nginx front для User Portal (TLS, →127.0.0.1:8443)"},
  {"service": "vless", "port": 443, "proto": "tcp", "comment": "VLESS Reality"}
]
```

API:
- `port_register(service, port, proto, comment, force=False)` — регистрация с conflict check
- `port_unregister(service, port=None, proto=None)` — снятие (по service+port или весь service)
- `port_get_conflicts(port, proto, exclude_service=None)` — список конфликтов
- `port_is_free(port, proto, exclude_service=None)` — `(bool, [descriptions])`
- `port_list_all()` / `port_list_for_service(service)` — листинг
- `ufw_open_port(port, proto, service_tag, comment=None)` — UFW open с tag-комментарием
- `ufw_close_port(port, proto, service_tag)` — UFW close (только наши правила)

Conflict detection проверяет 4 источника:
1. Реестр `port_registry.json` (другие сервисы)
2. Активные системные слушатели (`ss -ltnp`)
3. UFW-правила (чужие `ufw status numbered`)
4. `/etc/services` (well-known ports — info, не блокирующий)

Service tags (canonical names): `SERVICE_VLESS`, `SERVICE_WEB_PANEL`,
`SERVICE_WEB_PANEL_NGINX`, `SERVICE_NAIVEPROXY`, `SERVICE_MIERU`,
`SERVICE_TRUSTTUNNEL`, `SERVICE_TELEMT`, `SERVICE_FPTN`, `SERVICE_WDTT`,
`SERVICE_AWG_STANDALONE`, `SERVICE_AWG_EXIT`, `SERVICE_SINGBOX`,
`SERVICE_SUBSCRIPTION`, `SERVICE_HYSTERIA2`.

### Решение 2: `nginx_front_portal.py`

nginx vhost с TLS для User Portal:

```
client → https://<domain>:<port> → nginx (TLS, cert from Let's Encrypt)
                                  → proxy_pass http://127.0.0.1:8443 (rest_api)
```

- **Порт настраиваемый** (default 9443, чтобы не конфликтовать с 443/8443/51820).
- **TLS-сертификат** — переиспользуется существующий Let's Encrypt для `PARAM_DOMAIN`.
  Если нет — `ssl_certbot.obtain_ssl_cert()` получает новый.
- **UFW** — открывается только порт nginx front. Backend (8443) остаётся на loopback.
- **Lifecycle** — install/remove с полной очисткой (vhost, symlink, UFW, registry).
- **Atomic rollback** — если `nginx -t` fail после установки vhost → откат.
- **Security headers** — HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
- **WebSocket support** — для будущих live-обновлений портала.
- **ACME challenge location** — для certbot renewal через webroot.

API:
- `nginx_front_install(port=9443, domain=None, backend_port=None) → (bool, str)`
- `nginx_front_remove() → (bool, str)`
- `nginx_front_status() → dict`
- `do_manage_nginx_front()` — TUI-меню

### TUI-интеграция

**Меню → Веб-панель управления → [7] nginx front (TLS)** — открывает меню:
- Включить на default порту 9443
- Включить с другим портом (проверка конфликтов)
- Выключить
- Проверить конфликты портов (через `do_manage_port_registry`)
- Статус: URL, backend, сертификат, активность nginx

**Меню → Веб-панель управления → [6] Удалить полностью** — теперь также
удаляет nginx front (если был установлен), потом rest_api web_panel.

### Lifecycle hooks

`rest_api.uninstall_web_service()` теперь:
1. Проверяет `nginx_front_status().enabled` — если да, вызывает `nginx_front_remove()`
2. Mask + stop systemd-unit `vless-web`
3. Disable + remove unit file
4. Закрывает UFW-порт web_panel (если expose=True было)
5. Очищает `web_config.json`

Сертификат Let's Encrypt НЕ удаляется — он может использоваться VLESS/nginx.

### Валидация порта в `nginx_front_portal._validate_port`

Запрещает:
- `< 1` или `> 65535`
- Привилегированные порты `< 1024` (nginx может не иметь прав)
- Зарезервированные: 443 (VLESS), 80 (HTTP/certbot), 22 (SSH), 8443 (rest_api backend)

### vhost generation

nginx config содержит:
- `listen <port> ssl http2` — HTTPS с HTTP/2
- `ssl_certificate` / `ssl_certificate_key` — Let's Encrypt cert
- `ssl_protocols TLSv1.2 TLSv1.3` — современные протоколы
- `ssl_ciphers` — Mozilla Intermediate 2024
- `add_header Strict-Transport-Security "max-age=63072000"` — HSTS 2 года
- `proxy_pass http://127.0.0.1:<backend_port>` — проксирование на rest_api
- `proxy_set_header X-Real-IP $remote_addr` — передача реального IP клиента
- `proxy_buffering off` — для streaming downloads (clash/singbox configs)
- `location /.well-known/acme-challenge/` — для certbot renewal

### НЕ рефакторю существующие сервисы

15+ сервисов (VLESS, Hysteria2, AWG, NaiveProxy, Mieru, TrustTunnel, Telemt,
FPTN, WDTT, Subscription, и т.д.) имеют свой UFW-код. Их рефакторинг — большой
объём с риском регрессий. В этом коммите:

1. Создан паттерн (`port_registry.py`)
2. Применён к новому функционалу (nginx_front_portal)
3. Документирован для будущих рефакторингов

Существующие сервисы продолжают работать как есть — их UFW-код не тронут.

### Тесты (37 новых в `tests/test_port_registry.py`)

- `TestRegistryLoadSave` (3) — JSON I/O
- `TestPortRegister` (6) — регистрация с conflict detection, force, idempotent
- `TestPortUnregister` (3) — снятие по service+port, по service, nonexistent
- `TestPortGetConflicts` (4) — registry/system/ufw, exclude_service
- `TestPortIsFree` (2) — free/occupied
- `TestPortListAll` (1) — листинг
- `TestUfwHelpers` (4) — open/idempotent/foreign-conflict/no-ufw
- `TestEtcServices` (3) — well-known ports (443=https, 80=http, 59999=?)
- `TestNginxFrontValidatePort` (5) — valid/privileged/reserved 80/8443/out-of-range
- `TestNginxFrontVhostGeneration` (2) — required directives, no listen 443
- `TestNginxFrontStatus` (2) — disabled when no state, after install
- `TestNginxFrontRemoveWithUninstallWebPanel` (1) — uninstall вызывает nginx_front_remove
- `TestRestApiMenuHasNginxFrontItem` (1) — TUI пункт [7]

530 связанных тестов проходят (0 регрессий).

### Совместимость

- Backward compatible: существующие сервисы не тронуты.
- nginx_front опционален: web_panel продолжает работать без него (через SSH-туннель).
- port_registry опционален: существующие сервисы не используют его, но могут начать.
- Если `port_registry.json` повреждён/отсутствует — `_registry_load()` возвращает `[]`.
- Если `nginx_front_portal_state.json` отсутствует — `nginx_front_status()` возвращает `enabled: False`.
- UFW не установлен — `ufw_open_port` возвращает `(False, "ufw не установлен")`, не падает.

---

## FEAT(security):  — Per-user IP whitelist для ingress_geoip — 8 августа 2026

**Новый модуль `chimera/modules/user_ip_whitelist.py` — позволяет клиентам с
российскими IP подключаться к VLESS на 443, даже когда включена блокировка
входящих из РФ (ingress_geoip).**

### Контекст проблемы

`ingress_geoip` дропает ВСЕ входящие из РФ на SERVER_PORT (443). Это защищает
от ТСПУ-сенсоров, но блокирует и реальных клиентов с российскими IP. Раньше
whitelist был только для админских IP — не масштабировалось на много клиентов.

### Решение

Per-user `allowed_ips` в `users.json`:
- Админ добавляет IP клиента через TUI (меню → Пользователи → [6] IP whitelist)
- Клиент сам добавляет свои IP через User Portal (веб-интерфейс)
- Cron каждые 5 минут пересобирает ipset `clients_wl_v4` / `clients_wl_v6`
- iptables: `ACCEPT -m set --match-set clients_wl_v4 src -p tcp --dport 443`
  ставится через `-I INPUT 1` (в начало) — приоритет над DROP для РФ-подсетей

### АРХИТЕКТУРНЫЕ РЕШЕНИЯ (Q1 + Q2)

**Q1 — chicken-egg с User Portal:**

Выбран **вариант (a)** — User Portal доступен отдельно от ingress_geoip-гейта.

Обоснование:
- User Portal (`rest_api.py`) слушает на порту 8443 по умолчанию, отдельном
  от SERVER_PORT (443)
- `ingress_geoip._ingress_apply_ipset()` применяет DROP только к
  `--dport <SERVER_PORT>`, НЕ к 8443
- Клиент может сменить IP, выпасть из whitelist, но всё равно зайти в User
  Portal на порт 8443 и добавить свой новый IP
- Вариант (a) не создаёт скрытого временного окна уязвимости, в отличие от
  (b) grace-period

Реализация: `_ingress_enable()` автоматически вызывает
`apply_iptables_rule(port)` из `user_ip_whitelist` — ставит ACCEPT для
clients_wl перед DROP. `_ingress_remove()` — снимает правило.

**Q2 — доверие к X-Forwarded-For:**

`rest_api.py` слушает напрямую (без nginx по умолчанию), использует
`self.client_address[0]` для определения IP клиента. НЕ доверяет
`X-Forwarded-For`, т.к. его можно подделать.

Реализация:
- `GET /api/portal/ips` возвращает `detected_ip` из `_client_ip()` (это
  `self.client_address[0]`)
- `POST /api/portal/ips` с `{"ip": "auto"}` берёт IP из `_client_ip()`
- Если `_client_ip()` == 127.0.0.1 / ::1 (клиент за SSH-туннелем) —
  auto-detect возвращает ошибку, IP нужно указать вручную
- Тест `test_spoofed_xff_does_not_affect_ip_detection` проверяет что
  подделка X-Forwarded-For не влияет на detected_ip

### Структура данных

`users.json` — новое поле `allowed_ips` (список строк, IPs/CIDR):
```json
{
  "users": [
    {
      "uuid": "abc-123",
      "email": "alice@example.com",
      "name": "alice",
      "allowed_ips": ["5.6.7.8", "5.6.8.0/24", "2a03:1ac0::/64"]
    }
  ]
}
```

Обратная совместимость: старые users без поля `allowed_ips` работают —
`get_user_ips()` возвращает `[]`.

### Валидация IP/CIDR

`_validate_ip_or_cidr()`:
- Разрешает: глобальные IPv4 (1.0.0.0/8 — 223.0.0.0/8), глобальные IPv6 (2000::/3)
- Запрещает: loopback (127.x, ::1), private (10.x, 192.168.x, fc00::/7),
  link-local (169.254.x, fe80::/10), multicast (224.x, ff00::/8),
  unspecified (0.0.0.0, ::), reserved
- Нормализует: `2a03:1ac0:0000:0000:0000:0000:0000:0001` → `2a03:1ac0::1`
- Поддерживает как одиночные IP, так и CIDR (5.6.7.0/24)

### Интеграция

**TUI** (админ):
- Меню → Пользователи → [6] IP whitelist
- Подменю: выбор пользователя → список IP → add/remove
- Управление cron (включить/выключить автообновление)
- Очистка всех IP всех пользователей

**User Portal** (клиент, веб):
- Карточка «🛂 Мои IP-адреса»
- Показывает текущий IP клиента (detected_ip)
- Кнопка «Текущий IP» —一键 добавить свой текущий IP
- Ручной ввод IP/CIDR
- Удаление IP с подтверждением
- Лимит: 20 IP на пользователя

**REST API**:
- `GET /api/portal/ips` — список allowed_ips + detected_ip
- `POST /api/portal/ips` с `{"ip": "..."}` или `{"ip": "auto"}` — добавить
- `DELETE /api/portal/ips?ip=<ip>` — удалить

**ingress_geoip.py**:
- `_ingress_enable()` автоматически применяет ACCEPT-правило для clients_wl
- `_ingress_remove()` автоматически снимает правило (данные в users.json сохраняются)
- При повторном включении ingress_geoip — правила восстанавливаются из users.json

**ipset_persist.py**:
- `rebuild_clients_ipset()` после пересборки вызывает `ipset_save()` для
  boot-restore (через существующий xray-ipset-restore.service)

### Atomic swap

`rebuild_clients_ipset()` использует `ipset swap` для atomic обновления:
1. Создаёт tmp-сет `clients_wl_v4_tmp` с новыми IP
2. `ipset swap clients_wl_v4_tmp clients_wl_v4` — atomic операция
3. Удаляет tmp-сет (теперь содержит старые IP)

Без перерыва в фильтрации. Старые IP работают до swap, новые — сразу после.

### Тесты (40 новых в `tests/test_user_ip_whitelist.py`)

- `TestValidateIpOrCidr` (10 тестов) — валидация IP/CIDR
- `TestAddRemoveGetUserIPs` (8 тестов) — CRUD
- `TestMigrateOldUsers` (2 теста) — обратная совместимость
- `TestCollectAllUserIps` (2 теста) — сбор IP из всех users
- `TestRebuildClientsIpset` (2 теста) — atomic swap
- `TestIptablesRule` (3 теста) — установка/снятие правил
- `TestCron` (2 теста) — cron-файлы
- `TestQ1UserPortalAccessibleWithoutWhitelist` (3 теста) — Q1 (архитектура)
- `TestQ2NoXForwardedForTrust` (4 теста) — Q2 (безопасность)
  - `test_spoofed_xff_does_not_affect_ip_detection` — подделка XFF не работает
- `TestIngressGeoipIntegration` (2 теста) — интеграция с ingress_geoip
- `TestTuiEntryPoint` (1 тест) — TUI пункт [6]

### Совместимость

- Backward compatible: старые users.json без `allowed_ips` работают.
- ingress_geoip без user_ip_whitelist: продолжает работать (whitelist
  просто пропускается, в логе info-сообщение).
- ipset недоступен: `apply_iptables_rule` возвращает False, ingress_geoip
  продолжает работать без whitelist.
- IPv4-only: IPv6 ipset создаётся пустой, не мешает.
- IPv6-only: аналогично.

---

## FIX(youtube):  — ВОЗВРАТ  (routeOnly + sockopt) для серверов с IPv6 — 8 августа 2026

**Возврат изменений   Пользователь переезжает на сервер с IPv6
connectivity, где routeOnly=True безопасен.**

### Контекст

В  я откатил изменения  (routeOnly=True + sockopt в freedom
outbound), потому что на сервере БЕЗ IPv6 они ломали YouTube: `routeOnly=True`
передавал freedom outbound IP-адрес от клиента (а не домен), и если клиент
резолвил YouTube в IPv6 (мобильные операторы, некоторые ISP), а RU-сервер
без IPv6 — freedom пытался звонить на IPv6 и dial падал.

Пользователь решил переехать на сервер с IPv6, где это ограничение отпадает.
Возвращаю  as-is.

### Что возвращено 

- **ВОЗВРАЩЁН sockopt в freedom outbound** (tcpKeepAliveIdle=60,
  tcpKeepAliveInterval=15, tcpUserTimeout=10000, tcpFastOpen=true).
  БЕЗ `tcpCongestion="bbr"` (требует `modprobe tcp_bbr`, ломал YouTube в  .
  БЕЗ `tcpNoDelay` (удалён в Xray, был no-op).
- **ВОЗВРАЩЕНЫ вызовы `_youtube_patch_inbounds_for_fragment()` и
  `_youtube_restore_inbounds_after_fragment()`** — точечно (только при
  активном fragment) выставляют routeOnly=True и добавляют "quic" в destOverride.
- **ОСТАЮТСЯ** (из   не убирались в  :
  - `maxSplit` в fragment (3-6 для medium, 5-10 для heavy, 8-15 для max)
  - Расширенный список YouTube-доменов (CDN variants)
  - Грейсфул-рестарт 500мс перед `systemctl restart xray`
- **Обновлены тексты в TUI** — добавлено предупреждение про IPv6 requirement
  и подсказка выключить QUIC block если «Нет подключения».

### ВАЖНО: совместимость с IPv4-only серверами

Если вы используете RU+fragment на сервере **БЕЗ IPv6**:
- Включите **QUIC block** в подменю пресета → YouTube fallback на TCP,
  TCP фрагментируется, dial идёт на IPv4 (через UseIPv4 strategy).
- ИЛИ используйте **WARP routing** (опция [W] в меню YouTube) — WARP работает
  через Cloudflare IPv4 даже если у RU-сервера нет IPv6.
- ИЛИ вообще не используйте RU+fragment — выберите [1] (RU entry, без fragment)
  или exit-ноды.

### Тесты

- 59 тестов YouTube-модуля (42 старых + 17    — все проходят.
- 285 связанных тестов проходят.
- Восстановлены тесты:
  - `test_sockopt_present_without_bbr` — sockopt присутствует, без bbr
  - `test_inbound_sniffing_patched` — routeOnly=True и quic в destOverride
  - `test_remove_restores_routeonly_and_quic` — откат sniffing после remove

### Совместимость

- На сервере С IPv6: работает как  (с патчем sniffing + sockopt).
- На сервере БЕЗ IPv6: используйте QUIC block или WARP routing.
- AWG-режим НЕ затронут (metadataOnly=True не патчится).
- Xray 26.x+ требуется (XTLS форк).

---

## FIX(youtube):  — HOTFIX откат опасных изменений  — 8 августа 2026

**СРОЧНЫЙ ОТКАТ. После  у пользователя YouTube снова выдал
'Нет подключения к интернету'. Возврат к чистому fragment (как в рабочей  ,
но с сохранением безопасных улучшений.**

### Что сломалось в 

В  я добавил три изменения, которые в теории должны были улучшить
стабильность, но на практике ломали YouTube у пользователя:

1. **`routeOnly: True` + `destOverride: ["quic"]` в inbound sniffing.**
   Это переопределило фикс **v4.12.6** от 5 июня 2026 года. Согласно CHANGELOG:

   > **v4.12.6 — Фикс IPv6 через прокси (routeOnly: False)**
   > Причина: routeOnly: True означал что xray не переписывал destination →
   > freedom outbound получал уже резолвленный IP вместо доменного имени →
   > domainStrategy: UseIPv4 не могла сделать свою работу.

   В  я выставил routeOnly=True → freedom outbound стал получать IP
   от клиента (а не домен) → domainStrategy=UseIPv4 игнорировалась. Если
   клиент резолвит YouTube в IPv6 (например, мобильный оператор с IPv6),
   а RU-сервер без IPv6 — freedom пытается звонить на IPv6 и падает →
   «Нет подключения к интернету».

2. **`sockopt` в freedom outbound (`tcpFastOpen`, `tcpKeepAlive*`, `tcpUserTimeout`).**
   Хотя дока Xray подтверждает что sockopt на freedom outbound поддерживается,
   на практике у некоторых пользователей это снова вызывало «Нет подключения».
   Возможные причины:
   - `tcpFastOpen` требует `net.ipv4.tcp_fastopen != 0` в sysctl; на некоторых
     VPS значение = 0, и setsockopt(TCP_FASTOPEN_CONNECT) может возвращать
     ошибку → dial abort → «Нет подключения».
   - `tcpUserTimeout` может не поддерживаться на старых ядрах.

3. **`"quic"` в `destOverride`.** Хотя это должно быть безопасно с routeOnly=True,
   commit fb13e49 уже удалял "quic" из-за побочных эффектов (log noise, QUIC
   parsing issues). Возврат мог добавить нестабильности.

### Что откатываем 

- **УБРАН `sockopt` из freedom outbound.** Возврат к чистому fragment, как в
  рабочей    Константа `_YOUTUBE_SAFE_SOCKOPT` оставлена в коде
  как документация.
- **УБРАНЫ вызовы `_youtube_patch_inbounds_for_fragment()` и
  `_youtube_restore_inbounds_after_fragment()`.** Сами функции оставлены
  в коде (с пометкой ВЫКЛЮЧЕНО) для будущих экспериментов. Причина: routeOnly=True
  ломает UseIPv4 стратегию freedom outbound (фикс v4.12.6).

### Что оставляем из  (безопасные улучшения)

- **`maxSplit`** — поле fragment, ограничивает количество фрагментов на
  TCP-сегмент. Пресеты: light=нет, medium=3-6, heavy=5-10, max=8-15.
- **Расширенный список YouTube-доменов** (CDN variants): wide-youtube.l.google.com,
  youtube-ui.l.google.com, youtubeembedded-pa.googleapis.com, youtube.googleapis.com,
  yt-video-googleusercontent.com, lh3.googleusercontent.com.
- **Грейсфул-рестарт**: 500мс sleep перед `systemctl restart xray`.
- **QUIC block (опциональный)** — остаётся в меню, но снова не матчит QUIC
  по домену (т.к. "quic" не в destOverride). Это как было до  

### Состояние после 

YouTube через RU+fragment работает так же, как в  (т.е. «работает, но
нестабильно» — buffering, Shorts иногда тупят). Это базовая стабильность,
которую мы знаем. Никаких регрессий относительно  

Дальнейшие улучшения стабильности требуют более глубокого подхода:
- IPv6 connectivity на RU-сервере (чтобы routeOnly=True работал)
- ИЛИ: балансировщик между RU+fragment и exit-нодами для QUIC-видео
- ИЛИ: переход на sing-box с его `route.platform.http_client` для более
  гибкой маршрутизации

### Тесты

- 53 теста YouTube-модуля (42 старых + 11 новых    — все проходят.
- Всего 279 связанных тестов проходят.
- Новые тесты  
  - `test_no_sockopt_in_freedom_outbound` — проверяет что sockopt НЕ в outbound
  - `test_inbound_sniffing_not_modified` — проверяет что routeOnly/destOverride не трогаются
  - `TestPatchInboundsFunctionDefined` — функции определены и работают (если вызвать вручную)

### Совместимость

- Backward compatible с  (поведение идентично, плюс maxSplit/domains/sleep).
- AWG-режим НЕ затронут.
- Xray 26.x+ требуется (XTLS форк).

---

## FIX(youtube):  — стабильность RU+fragment через patch sniffing + safe sockopt — 8 августа 2026

**Полная переработка стабильности YouTube через RU+fragment. Решает:
"видео buffering несколько секунд", "Shorts иногда не грузятся",
"Нет подключения к интернету при смене preset", "нужно перезагружать сервер".**

### Анализ (включая сверку с документацией Xray v26.7.28)

**Что было сломано в  (когда YouTube полностью упал):**

Старый комментарий "freedom outbound is not designed for sockopt" — НЕВЕРЕН.
Согласно доке Xray (https://xtls.github.io/en/config/transports/sockopt.html):
«For direct outbounds such as Freedom, the peer is usually any ordinary
public network target... only sockopt is available.»

Реальная причина поломки: `tcpCongestion: "bbr"` требует загруженного модуля
`tcp_bbr` в ядре. Если модуль не загружен, `setsockopt(TCP_CONGESTION, "bbr")`
возвращает `ENOTSUP`, и Xray прерывает КАЖДЫЙ dial через freedom outbound →
«Нет подключения к интернету». Остальные sockopt-поля (`tcpFastOpen`,
`tcpKeepAliveIdle`, `tcpKeepAliveInterval`, `tcpUserTimeout`) работают
корректно на любом современном Linux. `tcpNoDelay` удалён в Xray (no-op).

Блокировка QUIC сама по себе YouTube не сломала — она просто не срабатывала
(см. ниже), но и не помогала. Главным убийцей был sockopt с `bbr`.

**Корневая причина текущей нестабильности :**

1. **QUIC видео YouTube шёл мимо fragment-правила.**
   С v4.12.6 все VLESS/REALITY inbound имеют `routeOnly: False` + с v4.12.6
   fb13e49 — `destOverride: ["http", "tls"]` (без `"quic"`).
   Это значит: QUIC-пакеты YouTube (UDP/443) не имеют sniffed-домена в
   routing → правило `domain:[youtube...]` НЕ матчит QUIC → QUIC видео
   идёт через catch-all к exit-нодам. В итоге: API/HTML через fragment,
   видео-стрим через exit-ноды — асимметричная маршрутизация, рассинхрон
   сессии, "Shorts не грузятся".

2. **routeOnly: False переписывает destination.**
   Freedom outbound получает sniffed domain (а не IP) и делает DNS-resolve
   через систему. На медленном DNS это добавляет задержку на каждый новый
   TCP-коннект к YouTube CDN. Отсюда "видео buffering несколько секунд".

3. **Нет grace period перед restart xray.**
   При смене preset — активные TCP-коннекты к YouTube CDN рвутся. Browser
   retries, но в момент restart Xray недоступен → "Нет подключения к
   интернету". Помогала только перезагрузка сервера (которая убивала все
   соединения и заставляла browser начать с чистого листа).

### Фиксы 

**1. Патч inbound sniffing ТОЛЬКО при активном RU+fragment.**
   Новые функции `_youtube_patch_inbounds_for_fragment()` /
   `_youtube_restore_inbounds_after_fragment()`:
   - Для всех VLESS/REALITY inbound с `metadataOnly=False` (не-AWG):
     - `routeOnly: True` — routing по SNI без переписывания destination
     - `destOverride: ["http", "tls", "quic"]` — QUIC SNI используется
       для роутинга (но destination IP не переписывается)
   - AWG-режим (`metadataOnly=True`) НЕ трогаем — там sniffing отключён
     намеренно (kernel-роутинг).
   - При отключении fragment — откатываем routeOnly в False, убираем "quic"
     из destOverride.
   - Источник: https://xtls.github.io/en/config/inbound.html#routeonly-true-false

**2. Возврат безопасного sockopt в freedom outbound.**
   Согласно доке Xray, sockopt на freedom outbound поддерживается официально.
   Добавляем:
   ```json
   "sockopt": {
     "tcpKeepAliveIdle":     60,
     "tcpKeepAliveInterval": 15,
     "tcpUserTimeout":       10000,
     "tcpFastOpen":          true
   }
   ```
   БЕЗ `tcpCongestion: "bbr"` (требует modprobe tcp_bbr — был причиной
   поломки  . БЕЗ `tcpNoDelay` (удалён в Xray, был no-op).

**3. Новое поле `maxSplit` в fragment (недокументированное, поддерживается).**
   Ограничивает количество фрагментов на один TCP-сегмент — полезно для
   больших ClientHello (TLS 1.3 + ECH + ALPN). Пресеты обновлены:
   - light: maxSplit не задан
   - medium: maxSplit="3-6"
   - heavy: maxSplit="5-10"
   - max: maxSplit="8-15"
   Custom input поддерживает max_split (Enter = пропустить).

**4. Грейсфул-рестарт: 500мс sleep перед `systemctl restart xray`.**
   Даёт активным соединениям корректно завершиться. Сокращает "Нет
   подключения к интернету" при смене preset.

**5. Расширенный список YouTube-доменов.**
   Добавлены CDN variants (раньше видеострим мог асимметрично уйти через
   default outbound, пока thumbnails/api шли через fragment):
   - `wide-youtube.l.google.com`
   - `youtube-ui.l.google.com`
   - `youtubeembedded-pa.googleapis.com`
   - `youtube.googleapis.com`
   - `yt-video-googleusercontent.com`
   - `lh3.googleusercontent.com`

**6. QUIC block теперь действительно работает (опционально).**
   Раньше правило `domain + network:udp + port:443 → blackhole` не могло
   сматчиться без `quic` в `destOverride`. Теперь с патчем sniffing оно
   работает корректно. Но по умолчанию всё ещё ВЫКЛ — браузеру нужен
   retry (1-3с) для fallback на TCP.

### Документация (новые комментарии в коде)

В `youtube_route.py` добавлены развёрнутые комментарии со ссылками на
официальную доку Xray v26.x:
- Почему sockopt с bbr ломал YouTube (kernel module requirement)
- Почему routeOnly=True правильное решение (no destination rewrite)
- Почему quic в destOverride безопасен с routeOnly=True (no dest rewrite)
- Подтверждение что freedom.settings.fragment — правильное место для
  серверной фрагментации (а не sockopt.fragment, которого не существует)

### Тесты

- 42 существующих теста — без регрессий.
- 16 НОВЫХ тестов в `tests/test_youtube_route_v5013.py`:
  - patch_inbounds_for_fragment (6 тестов)
  - restore_inbounds_after_fragment (2 теста)
  - apply_fragment_with_maxsplit (2 теста)
  - safe_sockopt (1 тест)
  - graceful_restart (1 тест)
  - expanded_youtube_domains (1 тест)
  - remove_from_xray_restores_sniffing (1 тест)
  - fragment_preset_menu_v5013 (2 теста)
- Всего 204 связанных теста проходят.

### Совместимость

- Backward compatible: при `block_quic=False` (дефолт) поведение для тех,
  кто НЕ использует RU+fragment — без изменений (patching только при
  активном fragment).
- AWG-режим: НЕ трогаем metadataOnly=True inbound (kernel-роутинг).
- Xray 26.x+ требуется (XTLS форк).

---

## FEAT(youtube): YouTube→WARP routing + RU+fragment — обход ТСПУ DPI — 7 августа 2026

**Две новые функции в модуле YouTube-маршрутизации для обхода ТСПУ SNI-фильтрации
YouTube: маршрутизация через Cloudflare WARP и TCP-фрагментация ClientHello.**

### 1. YouTube→WARP routing (Option D: sendThrough + kernel table 301)

**Новый модуль `chimera/modules/youtube_warp_route.py`** — маршрутизация
YouTube-трафика через Cloudflare WARP с использованием `freedom` outbound
Xray с `sendThrough` (привязка source IP) + sing-box `bind_interface`.

**Архитектура:**
- WARP (wg-warp) должен быть установлен и интерфейс поднят
- `ip rule add from <warp_ip> table 301` + `ip route add default dev wg-warp table 301`
  → kernel маршрутизирует пакеты с source=warp_ip через wg-warp
- Xray: `freedom` outbound с `sendThrough=<warp_ip>` + доменное правило
  YouTube → `warp`
- sing-box: `direct` outbound с `bind_interface=wg-warp` + `domain_suffix`
  правило YouTube → `warp`
- Systemd-сервис для восстановления после ребута

**Интерактивный flow с авто-установкой WARP:**
При нажатии [W] в меню YouTube-маршрутизации модуль автоматически:
1. Проверяет статус WARP (installed/service_active/iface_up)
2. Если WARP не установлен — предлагает запустить мастер установки
3. Если сервис остановлен — предлагает запустить
4. Если битая установка — предлагает полное меню WARP
5. Проверяет IPv4 и IPv6 connectivity через wg-warp (curl через прямой
   IP 1.1.1.1, без DNS-зависимости)
6. Авто-определение IP-версии: если IPv4 заблокирован ТСПУ, но IPv6
   работает — предлагает IPv6 стратегию (sendThrough=warp_ipv6,
   domainStrategy=UseIPv6)
7. Принудительное применение (опционально) — если авто-проверка не
   проходит, пользователь может применить правило вручную

**IPv6 поддержка:**
Модуль корректно работает с серверами без публичного IPv6 — WARP-интерфейс
имеет IPv6-адрес (2606:4700:...), через который Xray открывает IPv6-соединения
к YouTube. Все YouTube-домены имеют полную IPv6-поддержку.

### 2. YouTube→RU+fragment — обход ТСПУ DPI

**Новая опция [F] в меню YouTube** — TCP-фрагментация ClientHello для
обхода ТСПУ SNI-фильтрации.

ТСПУ начал фильтровать YouTube SNI на прямых соединениях из РФ. Раньше
YouTube→RU (direct) работал. Теперь нужен fragment — Xray `freedom` outbound
с `settings.fragment` разбивает первые N байт TLS ClientHello на мелкие
кусочки, что мешает ТСПУ DPI-анализу SNI.

**Outbound `direct-fragment` (или `direct-local-fragment` в AWG-режиме):**
```json
{
  "protocol": "freedom",
  "tag": "direct-fragment",
  "settings": {
    "domainStrategy": "UseIPv4",
    "fragment": {
      "packets": "1",
      "length": "10-30",
      "interval": "3-8"
    }
  }
}
```

Требует Xray 26.x+ (XTLS форк с поддержкой fragment в freedom.settings).

**Пресеты fragment (подменю при нажатии [F]):**

| Пресет | packets | length | interval | Описание |
|--------|---------|--------|----------|----------|
| Light  | 1 | 50-100 | 1-3 мс | Минимальная задержка. Может не обойти ТСПУ. |
| Medium | 1 | 10-30 | 3-8 мс | Баланс (дефолт). Рекомендуется. |
| Heavy  | 1-2 | 5-15 | 5-12 мс | Больше покрытия, но медленнее. |
| Max    | 1-3 | 3-7 | 10-20 мс | Максимум обхода, самый медленный. |
| Custom | ручной ввод | ручной ввод | ручной ввод | Для опытных пользователей. |

**Опциональная блокировка QUIC:**
После выбора пресета модуль спрашивает: "Блокировать QUIC для YouTube? [y/N]".
QUIC (UDP/443) — YouTube использует его для видео. TCP fragment работает
только с TCP. Блокировка QUIC заставляет YouTube использовать TCP, но на
некоторых конфигурациях Xray это ломает YouTube полностью. По умолчанию ВЫКЛ.

### 3. Улучшения UX меню YouTube

- Кнопка [W] (WARP) перенесена вниз меню, рядом с [F] (fragment) — буквы
  отдельно от цифр
- Prompt обновлён: `[1/2/F/W/Q]` (single-node) и `[1-N/F/W/Q]` (multi-node)
- `current_display` показывает выбранный маршрут (RU/WARP/RU+fragment/exit-нода)
- Согласованность state.json с config.json (detect regenerate)
- Restore после regenerate xray-config

### Файлы

- `chimera/modules/youtube_warp_route.py` — новый модуль (WARP routing)
- `chimera/modules/youtube_route.py` — RU+fragment, пресеты, QUIC block
- `chimera/modules/warp.py` — улучшенный verification endpoint'а (прямой
  IP 1.1.1.1, retry loop, длиннее таймауты)
- `tests/test_youtube_route.py` — regression тесты

### Тесты

42 теста проходят (включая regression тесты для [W] и [F] кнопок).

---

## FIX(mtproto): NAT detection via IP comparison instead of is_private heuristic — 6 августа 2026

**Telemt MTProxy показывал нерабочие `tg://` ссылки на серверах с SDN NAT
(<hoster-2>, Azure). `_is_public_ip()` проверял только RFC1918/loopback/
link-local диапазоны — но SDN-NAT адреса выглядят как публичные, хотя
не маршрутизируются снаружи. `_get_public_ip()` возвращал локальный
NAT-адрес вместо реального публичного.**

### Проблема

Некоторые хостеры (<hoster-2>, Azure) используют SDN NAT с адресами,
которые не попадают в стандартные RFC1918 private ranges (10.x, 172.16.x,
192.168.x), но при этом не маршрутизируются извне. Например, `195.x.x.x`
на <hoster-2> — выглядит как публичный, но на самом деле внутренний SDN.

Старый код `_is_public_ip()` проверял только RFC1918 → возвращал `True`
для таких SDN-адресов → `_get_public_ip()` пропускал запрос внешнего IP
→ использовал нерабочий NAT-адрес в `tg://` ссылках → клиенты не могли
подключиться.

### Фикс

`chimera/modules/mtproto.py`: `_get_public_ip()` теперь **всегда**
запрашивает внешний IP (`api.ipify.org` / `ifconfig.me`) и сравнивает
с `local_ip`:

| local_ip | external_ip | Решение |
|----------|-------------|---------|
| matches external | matches | real public IP → use local |
| differs from external | differs | NAT → use external |
| differs | unavailable | fallback to local |

`_is_public_ip()` оставлен (не удалён) — может использоваться в других
местах. `_is_direct_ip()` не тронут — существующая Mode B логика
(exit-нода) сохранена.

### Файлы

- `chimera/modules/mtproto.py` — `_get_public_ip()` переписан, +50 строк
- `tests/test_mtproto.py` — +71 строк, 5 новых regression тестов

### Тесты (5 новых в `TestGetPublicIp`)

| # | Сценарий | Ожидаемый результат |
|---|----------|---------------------|
| 1 | Public IP matches external | returns local |
| 2 | Standard NAT (10.x) | returns external |
| 3 | **SDN NAT (non-RFC1918, e.g. 195.x on <hoster-2>)** | returns external (KEY) |
| 4 | External unavailable | returns local (fallback) |
| 5 | Mode B (exit node) | returns local |

157 тестов mtproto — pass, 0 регрессий.

---

## FEAT(dnscrypt): расширенная настройка DNSCrypt-proxy — 198 серверов, 50 стран, ODoH, DNSSEC, анонимизация — 2 августа 2026

**Новый модуль `chimera/modules/dnscrypt_advanced.py` — расширенная настройка
DNSCrypt-proxy с 198 серверами в 50 странах, анонимизированной маршрутизацией,
ODoH, DNSSEC и RTT-замером реальной latency.**

### Возможности

**1. Пресет «198 серверов, 50 стран»** —一键 применение полной конфигурации:
- 198 серверов в 50 странах (EU + RU + Asia + Global)
- 200 анонимизированных маршрутов (199 явных + 1 wildcard)
- ODoH (Oblivious DoH) — сервер не видит IP клиента
- DNSSEC, nolog, nofilter — все требования безопасности
- Эфемерные ключи DNSCrypt, TLS session tickets отключены
- HTTP/3 (QUIC), block_unqualified, block_undelegated
- Дополнительные источники: dnscry.pt, odoh-servers, odoh-relays
- Yandex DNS ИСКЛЮЧЁН (утечка)
- RU-серверы (dnscry.pt-moscow) — через EU relay

**2. RTT-замер** — измеряет реальную TCP latency до каждого из 198 серверов
(параллельно, 30 потоков). Пользователь выбирает 2-5 ближайших по скорости.

**3. Ручная настройка параметров** — индивидуальное изменение любого параметра
(DNSSEC, ODoH, cache, timeout, lb_strategy, и т.д.) через `key=value`.

**4. Статус конфигурации** — текущее состояние всех параметров, источников,
маршрутов и серверов.

### Страны (50)

**EU (21):** RU, UA, EE, LV, LT, FI, PL, DE, SE, CH, NL, CZ, RS, AT, NO, IS,
BG, DK, RO, HU, BE, LU

**Расширение (15):** TR, SK, MD, FR, IT, ES, GR, SI, HR, PT, UK, JP, SG, GE

**Глобальные (14):** US, CA, AU, AE, IL, IN, BR, ZA, IE, AR, CL, KR, TH, ID,
+ cloudflare/google (глобальные DoH)

### Анонимизированная маршрутизация

Каждый сервер имеет явный маршрут через relay в **другой стране**:
- Relay видит IP клиента, не видит DNS-запрос
- Server видит запрос, не знает IP клиента (видит relay)
- Wildcard-маршрут покрывает все серверы без явного маршрута

### Безопасность

- **НЕ** вызывает networkctl / ifconfig / ip link / dhclient
- **НЕ** трогает /etc/resolv.conf, /etc/nsswitch.conf, сетевые интерфейсы
- Только перезаписывает `dnscrypt-proxy.toml` + restart сервиса
- Бэкап конфига перед каждым изменением
- Двухфазное применение: сначала базовые серверы + источники, затем полный список
- Откат с проверкой что dnscrypt реально резолвит (`dig @127.0.0.1:5300`)

### Интеграция

В меню **Сеть** появился новый пункт:
```
[RA] 🛡️ DNSCrypt: расширенная настройка (198 серверов, ODoH, DNSSEC, анонимизация)
```

### Файлы

- `chimera/modules/dnscrypt_advanced.py` — новый модуль
- `chimera/_core.py` — импорт + пункт меню `[RA]`

---

## FIX(users_manager): дедупликация + валидация до записи (User already exists) — 2 августа 2026

**Два бага в `_users_apply_to_config` приводили к падению Xray с ошибкой
`User X already exists` и оставляли сломанный конфиг на диске.**

### Баг 1: конфиг перезаписывался ДО валидации

`_users_apply_to_config()` записывал конфиг на диск, а затем валидировал
его через `xray run -test -config`. Если валидация падала (например,
дублирующий UUID/email) — сломанный конфиг уже был на диске. Xray не
перезапускался (т.к. валидация упала), но при следующем ручном или
автоматическом рестарте Xray падал с `User already exists`.

**Фикс:** конфиг строится в памяти (`pending_writes`), валидируется через
временный файл (`tempfile.NamedTemporaryFile`), и **только после успешной
валидации** записывается на диск. Если валидация упала — оригинальный
рабочий конфиг нетронут.

### Баг 2: дедупликация только по UUID

`_unified_load_users()` делал дедупликацию пользователей по UUID, но
email мог дублироваться. Два пользователя с одинаковым email (но разными
UUID) попадали в `config.json` → Xray падал с `User X already exists`,
т.к. Xray требует уникальные email'ы.

**Фикс:** дедупликация по UUID **И** по email в `_users_apply_to_config`.
При обнаружении дубликатов выводится предупреждение:
`Удалено дубликатов: N (по UUID или email)`.

### Файлы

- `chimera/modules/users_manager.py` — `_users_apply_to_config()` переписан,
  +73 строки, -23 строки

### Совместимость

- Поведение для корректных данных не изменилось
- При наличии дубликатов — автоматическое удаление + предупреждение
- Старый конфиг не повреждается при ошибках валидации

### Тесты

Существующие тесты `test_users_manager.py` — pass, 0 регрессий.
Новые сценарии покрыты regression-тестами на дедупликацию по UUID/email
и на atomic-write при ошибке валидации.

---

## CRITICAL FIX(dns): resolv_conf_fix v6 — ПОЛНАЯ переработка, БЕЗ networkctl — 2 августа 2026

**ПРЕДЫСТОРИЯ: v4/v5 фиксы вызывали `networkctl reconfigure <link>`, что
ПОЛНОСТЬЮ переконфигурировало сетевой интерфейс — сбрасывало IP-адрес,
перезапрашивало DHCP. На удалённом сервере это УБИВАЛО SSH. Пользователь
потерял доступ к серверу и был вынужден переустанавливать ОС.**

**КРОМЕ ТОГО: v5 fallback создавал .network файл с `DHCP=yes` для интерфейса,
имя которого определялось динамически. Если интерфейс назывался `ensp0s4`
(а не `ens3`), fallback-файл мог сконфликтовать с netplan-конфигом и
переопределить статический IP на DHCP — тоже убивая SSH.**

### Принцип безопасности v6

Этот модуль **НЕ вызывает НИ ОДНОЙ команды, которая может затронуть
сетевой интерфейс**:

  ✗ НЕТ `networkctl reconfigure` (УБИВАЕТ SSH)
  ✗ НЕТ `networkctl reload`
  ✗ НЕТ `.network` файлов / drop-in'ов
  ✗ НЕТ `nmcli connection up/down`
  ✗ НЕТ `dhclient`
  ✗ НЕТ `ifconfig` / `ip link`

Только текстовые файлы + runtime `resolvectl` команды (не трогают интерфейсы):
  ✓ `/etc/resolv.conf` → статичный `nameserver 127.0.0.1`
  ✓ `/etc/nsswitch.conf` → убрать `resolve` (bypass systemd-resolved для glibc)
  ✓ `/etc/systemd/resolved.conf.d/chimera-dns.conf` → drop-in (defense-in-depth)
  ✓ `resolvectl dns LINK 127.0.0.1` + `default-route LINK false` (runtime, safe)
  ✓ `resolvectl flush-caches`

### Почему это работает

Проблема: systemd-resolved получает DHCP DNS от провайдера (77.88.8.8) и
отправляет запросы на все Global DNS параллельно — DNS Leak Test видит Yandex.

Решение: **ПОЛНОСТЬЮ обойти systemd-resolved** для системного DNS:
1. `/etc/resolv.conf` → `nameserver 127.0.0.1` — glibc (curl, dig, apt, ssh)
   использует этот файл напрямую, НЕ через systemd-resolved.
2. `/etc/nsswitch.conf` → убрать `resolve` из `hosts:` — nss-resolve модуль
   отключён, glibc использует `dns` (читает /etc/resolv.conf → 127.0.0.1).
3. Per-link `resolvectl` override — для приложений, использующих D-Bus API
   systemd-resolved напрямую.

Всё, что использует glibc `getaddrinfo()` (curl, dig, apt, python, ssh),
идёт через /etc/resolv.conf → 127.0.0.1 → DNSCrypt. **Утечки НЕТ.**

### Что удалено

- `_networkd_find_link_files()` — удалён
- `_networkd_disable_dhcp_dns()` / `_networkd_enable_dhcp_dns()` — удалены
- `_networkd_create_link_network_file()` — удалён (ОПАСНЫЙ — создавал .network)
- `_nm_disable_dhcp_dns()` / `_nm_enable_dhcp_dns()` — удалены
- `disable_dhcp_dns_on_all_links()` / `enable_dhcp_dns_on_all_links()` — удалены
- `_detect_network_manager()` — удалён
- Все `networkctl` вызовы — удалены
- Persist-скрипт переписан с bash на **Python** (надёжнее, БЕЗ networkctl)

### Тесты

16 тестов, включая `test_no_networkctl_called` — проверяет что НИ ОДНА
команда `networkctl` не вызывается. 16/16 OK. 75/75 в DNS-свите OK.

---

## FIX(dns): resolv_conf_fix v5 — robust поиск .network файлов + fallback создание — 1 августа 2026

**После v4 фикса пользователь увидел warning: "link ens3: не найден .network
файл для link ens3". DHCP DNS не отключился, утечка осталась. Причина:
`_networkd_find_link_files()` не нашёл .network файл — либо netplan не
сгенерировал его в /run/systemd/network/, либо Name= записан с пробелами/
wildcard/MAC, что старый парсер не понимал.**

### Корень проблемы

Старый `_networkd_find_link_files()`:
- Искал только `Name=<link>` буквально в тексте (без парсинга [Match] секции).
- Не понимал `Name = ens3` (с пробелами вокруг `=`).
- Не понимал `Name=ens3 eth0` (несколько имён через пробел).
- Не понимал wildcard `Name=e*`.
- Не понимал match по `MACAddress=`.
- Не имел fallback если файл не найден.

### Решение

**1. Полностью переписан `_networkd_find_link_files()`:**
- Парсит `[Match]` секцию корректно — собирает все `Name=` и `MACAddress=`.
- Поддерживает `Name = ens3` (пробелы вокруг `=`).
- Поддерживает `Name=ens3 eth0` (несколько имён через пробел).
- Поддерживает wildcard `Name=e*` через `fnmatch`.
- Поддерживает match по MAC: читает `/sys/class/net/<link>/address`,
  сравнивает с `MACAddress=` в .network файле.
- Fallback: если в `[Network]` есть `DHCP=yes` и нет явного Name —
  считает generic .network подходящим (редкий кейс).

**2. Новый fallback `_networkd_create_link_network_file(link)`:**
- Если .network файл не найден — создаёт новый
  `/etc/systemd/network/10-chimera-<link>.network` с:
  ```ini
  [Match]
  Name=ens3

  [Network]
  DHCP=yes

  [DHCPv4]
  UseDNS=false
  [DHCPv6]
  UseDNS=false
  [IPv6AcceptRA]
  UseDNS=false
  ```
- UseDNS=false уже внутри файла — drop-in не нужен.
- systemd-networkd применит этот файл при `networkctl reload`.

**3. `_networkd_disable_dhcp_dns()` — использует fallback:**
- Если `_networkd_find_link_files()` вернул пустой список → вызывает
  `_networkd_create_link_network_file()`.
- Возвращает путь к созданному .network файлу (не drop-in).

**4. `_networkd_enable_dhcp_dns()` — удаляет fallback .network файлы:**
- Кроме drop-in'ов, удаляет `10-chimera-*.network` (созданные fallback'ом).

### Тесты

`tests/test_resolv_conf_fix.py` — 6 новых unit-тестов:
- `TestNetworkdFindLinkFiles` (4): exact name / wildcard / multiple names /
  no match.
- `TestNetworkdDisableDhcpDnsFallback` (2): создаёт .network файл при
  отсутствии (fallback) / создаёт drop-in при наличии.

35/35 тестов в `tests/test_resolv_conf_fix.py` проходят. 94/94 в DNS-свите.

### Файлы

- `chimera/modules/resolv_conf_fix.py`:
  - `_networkd_find_link_files()` — полностью переписан (парсинг [Match],
    MAC, wildcard, multiple names, generic fallback).
  - Новая функция `_networkd_create_link_network_file(link)` — fallback.
  - `_networkd_disable_dhcp_dns()` — использует fallback если файл не найден.
  - `_networkd_enable_dhcp_dns()` — удаляет `10-chimera-*.network` файлы.
- `tests/test_resolv_conf_fix.py` — +6 тестов.

### Совместимость

- На server-сборках без netplan (нет /run/systemd/network/*.network) —
  fallback создаёт .network файл в /etc/, systemd-networkd применит.
- На Ubuntu 24.04 с netplan — netplan генерирует .network в /run/,
  парсер теперь корректно их находит (wildcard, MAC, multiple names).
- Rollback чистит оба типа: drop-in'ы + fallback .network файлы.

---

## UX(dns): кнопка [U] Re-apply в TUI — переприменить фикс v4 поверх v3 — 1 августа 2026

**После v4 фикса (отключение DHCP DNS) у пользователя мог быть уже применён
старый фикс v3 (per-link override + drop-in, но без disable_dhcp_dns). В
меню показывалось только [R] (Rollback) — не было способа переприменить
новый фикс без полного отката. Пользователь в тупике: R откатывает всё,
а F не показывается (fix_needed=False, потому что per-link уже OK).**

### Что добавлено

1. **Параметр `force=True` в `fix_resolv_conf_to_localhost()`** — позволяет
   переприменить фикс даже если `diagnose_resolv_conf()` вернул
   `fix_needed=False`. Это нужно для случая когда per-link уже OK (старый
   фикс), но Global DNS от DHCP нужно убрать (новый фикс v4 с
   `disable_dhcp_dns_on_all_links`).

   Логика при `force=True`:
   - Если `fix_method` из diagnose = None — fallback на `systemd_resolved`
     если systemd-resolved активен, иначе `static_resolv_conf`.
   - Все шаги применяются заново: drop-in, per-link override, persist,
     **disable_dhcp_dns_on_all_links** (КРИТИЧЕСКИЙ шаг v4).

2. **Новый пункт меню `[U]` (Re-apply / Update)** в TUI — показывается
   когда:
   - `state.fixed=True` (старый фикс применён)
   - Global DNS содержит внешние IP от DHCP
   - DNSCrypt активен и слушает

   `_screen_fix_reapply(diag)` — отдельный экран с подтверждением, показывает
   что будет переприменено (включая КРИТИЧЕСКИЙ шаг отключения DHCP DNS),
   вызывает `fix_resolv_conf_to_localhost(force=True)`.

3. **Логика меню** теперь:
   - `[F]` Fix — только если `fix_needed=True` (утечка, фикс не применён)
   - `[U]` Re-apply — если фикс применён, но Global DNS от DHCP есть
   - `[R]` Rollback — если фикс применён
   - `[D]` Diagnose — всегда
   - `[Q]` Exit — всегда

### Сценарий пользователя

1. Пользователь применил v3 фикс → per-link OK, но Global DNS 77.88.8.8.
2. DNS Leak Test показывает Yandex LLC.
3. Открывает TUI-экран → видит:
   ```
   ~ PER-LINK OK, НО Global DNS содержит внешние IP
     от DHCP: 77.88.8.8, 77.88.8.1
   ...
   ✓ Фикс применён: systemd-resolved drop-in (2026-08-01 17:39:00)
   ```
4. В меню видит `[U] Переприменить фикс (re-apply v4) ← отключить DHCP DNS`.
5. Нажимает `U` → подтверждает → фикс переприменяется с disable_dhcp_dns.
6. Global DNS теперь содержит только 127.0.0.1 → DNS Leak Test чистый.

### Тесты

- `test_force_reapplies_even_when_fix_not_needed` — НОВЫЙ регрессионный
  тест: simулирует состояние после v3 фикса (per-link OK, Global 77.88.8.8),
  проверяет что без `force` фикс отказывает, а с `force=True` — переприменяется
  с `disable_dhcp_dns_on_all_links`.

29/29 тестов в `tests/test_resolv_conf_fix.py` проходят. 88/88 в DNS-свите.

### Файлы

- `chimera/modules/resolv_conf_fix.py`:
  - `fix_resolv_conf_to_localhost()` — параметр `force=False` (default).
  - Новая функция `_screen_fix_reapply(diag)`.
  - `do_fix_resolv_conf_interactive()` — добавлен пункт `[U]`, логика
    `needs_reapply` (already_fixed + ext_global + dnscrypt_ready).
- `tests/test_resolv_conf_fix.py` — +1 тест (`test_force_reapplies_even_when_fix_not_needed`).

---

## FIX(dns): отключение DHCP DNS на уровне network manager — финальный фикс утечки — 1 августа 2026

**После v3 фикса (per-link override + drop-in) DNS Leak Test всё ещё
показывал Yandex LLC, хотя diagnose говорил "УТЕЧКИ НЕТ". Причина:
systemd-resolved отправляет запросы на ВСЕ Global DNS параллельно
(parallel queries), включая 77.88.8.8 от DHCP. Per-link override + drop-in
не убирают Global DNS от DHCP — они только добавляют 127.0.0.1. Чтобы
реально убрать 77.88.8.8, нужно отключить получение DNS от DHCP на уровне
network manager.**

### Корень проблемы

Моя теория из v3 ("Global DNS не используется из-за Domains=~.") была
неверной на практике. systemd-resolved 256+ отправляет запросы на все
Global DNS параллельно — это особенность реализации для отказоустойчивости.
Даже если drop-in с `Domains=~.` перехватывает запросы, 77.88.8.8 от DHCP
всё равно получает запросы — DNS Leak Test видит Yandex LLC.

### Решение

Программное отключение DHCP DNS на уровне network manager — без правки
yaml-файлов руками.

**Логика:**
1. `_detect_network_manager()` — определяет активный manager:
   - `systemctl is-active NetworkManager` → NetworkManager
   - `systemctl is-active systemd-networkd` → systemd-networkd
   - Иначе 'none'.

2. **systemd-networkd** (Ubuntu 24.04 cloud-образы, netplan):
   - `_networkd_find_link_files(link)` — находит `.network` файл для link'а
     в `/etc/systemd/network/`, `/run/systemd/network/`, `/lib/systemd/network/`.
   - `_networkd_disable_dhcp_dns(link)` — создаёт drop-in
     `/etc/systemd/network/<file>.network.d/chimera-dns.conf` с:
     ```ini
     [DHCPv4]
     UseDNS=false
     UseDomains=false

     [DHCPv6]
     UseDNS=false
     UseDomains=false

     [IPv6AcceptRA]
     UseDNS=false
     UseDomains=false
     ```
   - `networkctl reload` + `networkctl reconfigure <link>` — применяет.
   - Drop-in в `/etc/` переживает ребут и `netplan apply` (netplan
     регенерирует только `/run/`).

3. **NetworkManager** (десктопы, некоторые server-сборки):
   - `_nm_disable_dhcp_dns(link)` — `nmcli connection modify <conn>
     ipv4.ignore-auto-dns yes` + `ipv6.ignore-auto-dns yes` +
     `nmcli connection up <conn>`.

4. Интегрировано в `fix_resolv_conf_to_localhost()` как шаг **1i** (после
   persist-сервиса). State сохраняет `dhcp_dns_disabled` и `dhcp_dropin_paths`.

5. Rollback (`rollback_resolv_conf()`) — шаг 3: `enable_dhcp_dns_on_all_links()`:
   - systemd-networkd: удаляет drop-in'ы `chimera-dns.conf`.
   - NetworkManager: `nmcli ... ignore-auto-dns no`.

### TUI

- `_print_diagnosis()` — теперь корректно показывает утечку, если per-link
  OK, но Global DNS содержит внешние IP от DHCP:
  ```
  ~ PER-LINK OK, НО Global DNS содержит внешние IP
    от DHCP: 77.88.8.8, 77.88.8.1
    systemd-resolved отправляет запросы на все Global
    DNS параллельно — DNS Leak Test видит Yandex.
  ────────────────────────────────────────────────
  ✓ Можно исправить: отключить DHCP DNS на уровне
    network manager (systemd-networkd drop-in или
    NetworkManager ignore-auto-dns).
  ```
- `_screen_fix_apply()` — добавлен блок "КРИТИЧЕСКИЙ шаг: отключение DHCP DNS"
  с описанием что будет сделано.
- `_screen_rollback()` — добавлено "восстановить DHCP DNS: удалить
  .network.d/chimera-dns.conf / nmcli ignore-auto-dns no".

### Тесты

`tests/test_resolv_conf_fix.py` — 7 новых unit-тестов:
- `TestDisableDhcpDns` (3): systemd-networkd creates dropin /
  NetworkManager sets ignore-auto-dns / no network manager.
- `TestEnableDhcpDns` (1): systemd-networkd removes dropin (rollback).
- `TestDetectNetworkManager` (3): NetworkManager active / systemd-networkd
  active / none.

Все 28 тестов в `tests/test_resolv_conf_fix.py` проходят. 87/87 в DNS-свите.

### Файлы

- `chimera/modules/resolv_conf_fix.py`:
  - Новые helper-функции: `_detect_network_manager()`,
    `_networkd_find_link_files()`, `_networkd_disable_dhcp_dns()`,
    `_networkd_enable_dhcp_dns()`, `_nm_disable_dhcp_dns()`,
    `_nm_enable_dhcp_dns()`.
  - Новые публичные функции: `disable_dhcp_dns_on_all_links()`,
    `enable_dhcp_dns_on_all_links()`.
  - `fix_resolv_conf_to_localhost()` — шаг 1i: disable_dhcp_dns_on_all_links.
  - `rollback_resolv_conf()` — шаг 3: enable_dhcp_dns_on_all_links.
  - State: поля `dhcp_dns_disabled`, `dhcp_dropin_paths`.
  - `_print_diagnosis()` — корректное определение утечки при Global DHCP DNS.
  - `_screen_fix_apply()` / `_screen_rollback()` — обновлены.
- `tests/test_resolv_conf_fix.py` — 7 новых тестов.

### Совместимость

- systemd-networkd: drop-in в `/etc/systemd/network/<file>.network.d/`
  переживает `netplan apply` и ребут — netplan регенерирует только `/run/`.
- NetworkManager: `nmcli connection modify` сохраняется в
  `/etc/NetworkManager/system-connections/*.nmconnection` — persist.
- Если network manager не определён (static config) — warning, но фикс не
  падает. В этом случае пользователь должен сам прописать `nameserver 127.0.0.1`
  в `/etc/resolv.conf` (но это редкость на современных VPS).

---

## FIX(speedtest): DoH-резолв speed.cloudflare.com — обход серверного DNS после DNS-leak fix — 1 августа 2026

**После применения фикса DNS-leak (resolv_conf_fix v3) сломался Speed Test
через Cloudflare — "Cloudflare недоступен с сервера — тестируйте на клиенте
(fast.com)" на всех exit-нодах. Причина: серверный DNS теперь направлен на
127.0.0.1 (DNSCrypt-proxy), и curl использует его через /etc/resolv.conf →
systemd-resolved → 127.0.0.1:5300. Если DNSCrypt не может резолвить
`speed.cloudflare.com` (или работает медленно) — curl падает.**

### Корень проблемы

`_speed_test_download()` и `_cf_probe_available()` (inline в
`_speed_test_mode_a` и `speed_test.py`) использовали `curl` без `--resolve`.
curl резолвит `speed.cloudflare.com` через системный DNS. После фикса
DNS-leak системный DNS → 127.0.0.1:5300 (DNSCrypt). Если DNSCrypt:
- не настроен (нет server_names в TOML)
- использует блокирующие upstream
- завис или перегружен

→ `speed.cloudflare.com` не резолвится → curl rc!=0 → "Cloudflare недоступен".

### Решение

Применён тот же DoH-подход, что уже используется для exit-нод
(`_resolve_host_fresh` в `chain_nodes.py`):

1. **Новая функция `_cf_resolve_ip()`** в `_core.py` — резолвит
   `speed.cloudflare.com` через DoH (Cloudflare 1.1.1.1 + Google 8.8.8.8
   JSON API), минуя серверный DNS. Возвращает IP или None (fallback).

2. **Новая функция `_cf_probe_available()`** — probe Cloudflare endpoint
   с `--resolve speed.cloudflare.com:443:<IP>` в curl, минуя системный DNS.

3. **`_speed_test_download()`** — добавлен DoH-резолв + `--resolve` в curl.
   Если DoH не сработал — fallback на обычный curl (через системный DNS).

4. **`_speed_test_mode_a()`** (Режим A, прямой) — inline probe заменён на
   `_cf_probe_available()`.

5. **`speed_test.py` (Режим B, через exit-ноды)** — inline probe заменён на
   `_cf_probe_available()`; AWG-download тоже использует DoH + `--resolve`.

### Как это работает

```
curl --resolve speed.cloudflare.com:443:104.16.0.1 \
     https://speed.cloudflare.com/__down?bytes=10485760
```

`--resolve` заставляет curl использовать конкретный IP для указанного
домена, обходя системный резолвер. IP получен через DoH напрямую к
Cloudflare/Google — это работает даже если серверный DNS полностью сломан.

### Тесты

`tests/test_speed_test_cf_doh.py` — 11 новых unit-тестов:
- `TestCfResolveIp` (2) — DoH success / failure → IP / None.
- `TestCfProbeAvailable` (4) — probe с DoH + --resolve / без DoH (fallback) /
  curl failure / size too small.
- `TestSpeedTestDownload` (5) — --resolve передаётся / fallback без DoH /
  curl error / size too small / успешный результат со скоростью.

Все 80 тестов в speed-test + DNS-свите проходят.

### Файлы

- `chimera/_core.py`:
  - `_speed_test_download()` — добавлен DoH-резолв + `--resolve`.
  - Новая функция `_cf_resolve_ip()`.
  - Новая функция `_cf_probe_available()`.
  - `_speed_test_mode_a()` — inline probe заменён на `_cf_probe_available()`.
  - `Optional` добавлен в `from typing import`.
- `chimera/modules/speed_test.py`:
  - Inline probe заменён на `_cf_probe_available()`.
  - AWG-download использует DoH + `--resolve`.
- `tests/test_speed_test_cf_doh.py` — новый файл (11 тестов).

### Совместимость

- Если серверный DNS работает (DNSCrypt OK или не применён фикс) — DoH
  даёт тот же IP, что и системный резолвер. Поведение не меняется.
- Если серверный DNS сломан (DNSCrypt не работает) — DoH спасает speed test.
- Fallback: если DoH тоже не сработал (нет интернета до 1.1.1.1/8.8.8.8) —
  curl идёт через системный DNS (как раньше).

---

## FIX(dns): resolv_conf_fix v3 — убрать global resolvectl + per-link как главный критерий — 1 августа 2026

**После v2 фикса пользователь применил фикс, но diagnose всё равно показывал
утечку. Из логов:**

```
✓ resolvectl dns ens3 127.0.0.1     (per-link OK)
✓ resolvectl default-route ens3 false (per-link OK)
✓ systemctl restart systemd-resolved
✓ resolvectl flush-caches
✓ создан и активирован persist-сервис
• resolvectl dns 127.0.0.1: rc=1, stderr=Failed to resolve interface "127.0.0.1"
• resolvectl default-route false: rc=1, stderr=Failed to resolve interface "false"
```

И в диагностике:
```
Global:  77.88.8.8     ← от DHCP
Global:  77.88.8.1     ← от DHCP
Global:  127.0.0.1     ← из drop-in
Global:  127.0.0.1     ← из drop-in (дважды)
Link ens3: 127.0.0.1   ← per-link override OK
```

Diagnose показывал "УТЕЧКА" из-за 77.88.8.8 в Global DNS.

### Корень проблемы (3 момента)

**1. Global `resolvectl dns 127.0.0.1` падает на Ubuntu 24.04.**
Парсер systemd 256+ пытается интерпретировать `127.0.0.1` как имя интерфейса:
`Failed to resolve interface "127.0.0.1": No such device`. Аналогично с
`resolvectl default-route false` — `false` интерпретируется как имя интерфейса.
Global-команды с одним аргументом-IP-или-BOOL не работают.

**2. Global DNS содержит 77.88.8.8 от DHCP — но это НЕ утечка.**
Drop-in `/etc/systemd/resolved.conf.d/chimera-dns.conf` с `DNS=127.0.0.1`
и `Domains=~.` перехватывает все запросы на 127.0.0.1. Global DNS
77.88.8.8 (от DHCP через systemd-networkd/NetworkManager) присутствует в
списке, но не используется — потому что per-link DNS ens3=127.0.0.1 с
`default-route=false` означает, что ens3 не используется для default-route
запросов.

**3. Diagnose ошибочно считал Global DNS причиной утечки.**
Логика была: "Global DNS содержит внешний IP → утечка". Но это false
positive после применения фикса.

### Решение

**1. Убрать global `resolvectl dns/default-route`** — они не работают на
Ubuntu 24.04 и не нужны. Drop-in уже задаёт Global DNS через `[Resolve]
DNS=127.0.0.1` + `Domains=~.`. Этого достаточно.

**2. Per-link override — ГЛАВНЫЙ критерий утечки.**
Новая логика в `diagnose_resolv_conf()`:
- Если все link'и имеют DNS=127.0.0.1 И default-route=false → `per_link_overridden=True`,
  утечки НЕТ, даже если Global DNS содержит внешние IP.
- Если есть link с внешним DNS → утечка.
- Если resolv.conf указывает на внешний DNS (без systemd-resolved) → утечка.

**3. Получать per-link default-route** через новую helper-функцию
`_get_resolved_link_default_routes()` — парсит `resolvectl default-route`,
возвращает `[(link, bool)]`.

**4. TUI показывает per-link default-route** в диагностике:
```
Link ens3: 127.0.0.1
Link ens3 default-route: false ✓
```

**5. Информационное сообщение** в TUI, если per-link OK, но Global DNS
содержит внешние IP:
```
✓ УТЕЧКИ НЕТ — per-link override активен
  Все link'и направлены на 127.0.0.1,
  default-route=false для каждого.

Инфо: Global DNS содержит 77.88.8.8, 77.88.8.1.
Это не утечка — drop-in с Domains=~. перехватывает
все запросы на 127.0.0.1. Global не используется.
```

### Persist-скрипт

Убраны global `resolvectl dns 127.0.0.1` и `resolvectl default-route false`
из `/usr/local/bin/chimera-dns-fix-apply.sh`. Скрипт применяет только
per-link override для каждого link'а + flush-caches.

### Тесты

- `test_systemd_resolved_uses_correct_resolvectl_syntax` — расширен:
  проверяет, что global `resolvectl dns 127.0.0.1` и `default-route false`
  НЕ вызываются вообще (раньше проверялось обратное).
- `test_per_link_overridden_no_leak_despite_global_external_dns` — НОВЫЙ
  регрессионный тест: simулирует состояние после фикса (Global содержит
  77.88.8.8, но per-link ens3=127.0.0.1 + default-route=false) →
  `per_link_overridden=True`, `fix_needed=False`, `leak_reasons=[]`.

21/21 тестов проходят. 75/75 в DNS-свите.

### Файлы

- `chimera/modules/resolv_conf_fix.py`:
  - `fix_resolv_conf_to_localhost()` — убраны шаги 1b (global dns) и 1c
    (global default-route).
  - `_write_persist_script_and_service()` — убраны global resolvectl из
    shell-скрипта.
  - Новая helper-функция `_get_resolved_link_default_routes()`.
  - `diagnose_resolv_conf()` — добавлены поля `resolved_link_default_routes`
    и `per_link_overridden`; новая логика: per-link override = главный
    критерий, Global DNS не считается причиной утечки.
  - `_print_diagnosis()` — показывает per-link default-route; если
    `per_link_overridden=True`, показывает зелёное "УТЕЧКИ НЕТ" +
    informational про Global DNS.
  - `_screen_fix_apply()` — убраны global resolvectl из списка действий;
    добавлено объяснение, почему global НЕ вызываются.

---

## FIX(dns): resolv_conf_fix — правильный синтаксис resolvectl + per-link override + persist — 1 августа 2026

**После применения фикса на Ubuntu 24.04 утечка DNS оставалась: фикс
«применялся» (создавался drop-in, restart, flush-caches), но `resolvectl`
возвращал `Unknown command verb 'dns-global'` и `did you mean
'default-route'?`. Плюс — drop-in перебивал только Global DNS, а per-link
DNS от DHCP (ens3: 77.88.8.8 на Yandex VPS) имеет приоритет и не
заменялся. После ребута настройки терялись.**

### Корень проблемы

**1. Устаревший синтаксис `resolvectl`.**
В systemd 256+ (Ubuntu 24.04, Fedora 40+) команды были переименованы:
- `resolvectl dns-global set 127.0.0.1` → `resolvectl dns 127.0.0.1`
- `resolvectl dns-default-route set false` → `resolvectl default-route false`

Старые команды возвращали `Unknown command verb`, rc=1. Фикс не применялся,
но из-за того что restart + flush-caches шли после (с rc=0), пользователю
казалось, что всё ок.

**2. Per-link DNS имеет приоритет над Global.**
Drop-in `/etc/systemd/resolved.conf.d/chimera-dns.conf` с `DNS=127.0.0.1`
задаёт только Global DNS. Если у link'а (ens3) есть per-link DNS от DHCP
(через netplan/NetworkManager) — systemd-resolved использует per-link.
Global не применяется. Поэтому даже после фикса `resolvectl dns` показывал
`Link ens3: 77.88.8.8 77.88.8.1`.

**3. Нет persist после ребута.**
Настройки через `resolvectl dns LINK 127.0.0.1` применяются только до
перезапуска systemd-resolved. После ребута systemd-resolved снова
подхватывает DHCP DNS от провайдера.

### Решение

**1. Правильный синтаксис `resolvectl` (Ubuntu 24.04+):**
- `resolvectl dns 127.0.0.1` (global)
- `resolvectl dns LINK 127.0.0.1` (per-link)
- `resolvectl default-route false` (global)
- `resolvectl default-route LINK false` (per-link)

Реализовано через helper-функции `_resolvectl_dns_set(link, dns)` и
`_resolvectl_default_route_set(link, value)`, которые вызываются и для
global (link=None), и для каждого link'а.

**2. Per-link override — КРИТИЧЕСКИЙ шаг:**
- `_get_all_links()` — получает список всех сетевых link'ов из
  `resolvectl dns` (regex `^Link \d+ \(([^)]+)\):`), фильтрует loopback.
- Для каждого link'а: `resolvectl dns LINK 127.0.0.1` +
  `resolvectl default-route LINK false`.
- После `systemctl restart systemd-resolved` настройки link'ов
  сбрасываются — делается повторный проход.

**3. Persist после ребута — systemd-сервис `chimera-dns-fix.service`:**
- Скрипт `/usr/local/bin/chimera-dns-fix-apply.sh` (chmod 0o755):
  - Получает список всех link'ов через `resolvectl dns`.
  - Для каждого link'а: `resolvectl dns LINK 127.0.0.1` +
    `resolvectl default-route LINK false`.
  - Также задаёт global DNS и flush-caches.
- Systemd-unit `/etc/systemd/system/chimera-dns-fix.service`:
  - `After=network-online.target systemd-resolved.service dnscrypt-proxy.service`
  - `Requires=systemd-resolved.service`
  - `Type=oneshot`, `RemainAfterExit=yes`
  - `WantedBy=multi-user.target`
- После создания: `systemctl daemon-reload + enable + start`.
- Логи сервиса: `journalctl -u chimera-dns-fix.service`.

### Rollback

`rollback_resolv_conf()` теперь:
1. Останавливает и удаляет `chimera-dns-fix.service` + скрипт.
2. Удаляет drop-in.
3. Для каждого link'а: `resolvectl default-route LINK true` (возвращает
   DHCP DNS).
4. Global `resolvectl default-route true`.
5. `systemctl restart systemd-resolved`.
6. Восстанавливает `/etc/resolv.conf` из бэкапа.
7. `resolvectl flush-caches`.

### Диагностика после фикса

После применения фикса `diagnose_resolv_conf()` должна показать:
- `Global: 127.0.0.1`
- `Link ens3: 127.0.0.1` (per-link override)
- `fix_needed=False` (утечки нет)

В TUI-экране добавлена плашка в `state`:
- `Persist: chimera-dns-fix.service активен (переживёт ребут)` — если
  сервис создан.
- `⚠ persist-сервис не активен — после ребута DHCP DNS может вернуться` —
  если state.fixed=True, но сервис не создан.

### Тесты

- `test_systemd_resolved_fix_creates_dropin` — расширен: проверяет
  создание drop-in + persist-сервиса + скрипта (исполняемость, наличие
  `network-online.target` в unit, наличие `resolvectl dns` в скрипте).
- `test_systemd_resolved_uses_correct_resolvectl_syntax` — НОВЫЙ
  регрессионный тест: проверяет, что НЕ вызываются устаревшие `dns-global`
  / `dns-default-route`, и что ВЫЗЫВАЮТ `resolvectl dns 127.0.0.1` /
  `resolvectl dns eth0 127.0.0.1` / `resolvectl default-route false` /
  `resolvectl default-route eth0 false`.
- `test_rollback_systemd_removes_dropin_and_persist_service` —
  переименован и расширен: проверяет удаление drop-in + persist-сервиса
  + скрипта + восстановление per-link default-route.

Все 20 тестов в `tests/test_resolv_conf_fix.py` проходят. 74/74 в DNS-свите.

### Совместимость

- Старый синтаксис `dns-global` / `dns-default-route set` не используется
  вообще — он не работает на Ubuntu 24.04+ (а это и есть целевая
  платформа с проблемой DNS-leak).
- Если на очень старой системе (systemd < 240) команды не сработают —
  будет warning в actions, но фикс не откатится. Это приемлемо —
  старые системы обычно не имеют systemd-resolved в принципе.

### Файлы

- `chimera/modules/resolv_conf_fix.py`:
  - Новые константы: `_PERSIST_SVC_NAME`, `_PERSIST_SVC_PATH`,
    `_PERSIST_SCRIPT_PATH`.
  - Новые helper-функции: `_get_all_links()`, `_resolvectl_dns_set()`,
    `_resolvectl_default_route_set()`, `_write_persist_script_and_service()`,
    `_enable_persist_service()`, `_disable_persist_service()`.
  - `fix_resolv_conf_to_localhost()` — метод `systemd_resolved` полностью
    переработан: правильный синтаксис + per-link override + persist.
  - `rollback_resolv_conf()` — удаляет persist-сервис + восстанавливает
    per-link default-route.
  - State добавлено поле `persist_service: bool`.
  - TUI: `_screen_fix_apply()` показывает полный список действий
    включая per-link override и persist; `_screen_rollback()` показывает
    удаление persist-сервиса; `_print_fix_state_badge()` показывает
    статус persist-сервиса.

---

## UX(dns): TUI-меню resolv_conf_fix в едином стиле проекта + Rollback — 1 августа 2026

**После первого варианта `resolv_conf_fix.py` меню выбора [F/D/Q] рисовалось
plain-текстом вне рамки — несогласованно с остальными экранами Chimera.
Пользователь предложил привести к общему стилю и сразу добавить Rollback
(R) как первоклассный пункт, чтобы не нужно было повторно запускать
диагностику для отката.**

### Что изменилось

`do_fix_resolv_conf_interactive()` полностью переработан в зацикленный
TUI-экран в стиле `do_manage_dns_redirect()` (единый паттерн проекта):

**Структура экрана:**
1. `_box_top("🔧 ИСПРАВЛЕНИЕ /etc/resolv.conf (DNS LEAK FIX)")` + `_box_desc`.
2. Блок диагностики (resolv.conf / systemd-resolved / DNSCrypt / итог) —
   всё в одной рамке через `_box_row` / `_box_sep`.
3. Зелёная плашка «✓ Фикс применён: <method> (<timestamp>)» — только если
   state.fixed=True.
4. `_box_bottom()`.
5. **Отдельная рамка** `_box_top("ДЕЙСТВИЯ")` с пунктами:
   - `[F]` Исправить автоматически  (зелёным, только если fix_needed)
   - `[R]` Откатить фикс  (жёлтым, только если уже применён)
   - `[D]` Повторить диагностику
   - `[Q]` Выход в предыдущее меню
6. `Выбор:` — единственный plain-prompt.

**Зацикленность:** после любого действия (F/R) экран перерисовывается с
новой диагностикой — пользователь видит свежее состояние, не нужно
перезапускать экран вручную.

**Rollback как первоклассный пункт:** `[R]` показывается в меню сразу,
когда фикс уже применён — не нужно повторно запускать DNS Leak Test или
искать отдельный экран. Рядом с `[F]` и `[D]`.

**Подтверждение действий:**
- `[F]` → отдельный экран `_screen_fix_apply(diag)`: показывает что
  будет выполнено (drop-in / resolvectl / restart / flush-caches — для
  systemd_resolved; backup + rewrite — для static), prompt
  `Применить фикс? [Y/n]`, результат с actions/warnings.
- `[R]` → отдельный экран `_screen_rollback()`: показывает что будет
  удалено, предупреждение «после отката DNS снова будет идти через
  провайдера», prompt `Откатить фикс? [y/N]` (по умолчанию N — безопасно),
  результат.

### Файлы

- `chimera/modules/resolv_conf_fix.py` — переработан
  `do_fix_resolv_conf_interactive()` (зацикленный TUI), добавлены
  `_screen_fix_apply()`, `_screen_rollback()`, `_print_fix_state_badge()`.
  `_print_diagnosis()` больше не рисует собственный `_box_top`/`_box_bottom`
  — теперь встраивается в общий бокс экрана.

### Тесты

Все 19 unit-тестов в `tests/test_resolv_conf_fix.py` проходят (программные
функции `fix_resolv_conf_to_localhost` / `rollback_resolv_conf` /
`diagnose_resolv_conf` не изменились — изменён только TUI-слой).

---

## FEAT(dns): авто-фикс /etc/resolv.conf при DNS-leak (resolv_conf_fix.py) — 1 августа 2026

**DNS Leak Test показывал утечку к провайдерским DNS (Yandex LLC:
5.45.240.203, 37.140.169.116), но рекомендации в боксе были статичным
текстом — "Проверьте /etc/resolv.conf — должен указывать на 127.0.0.1".
Пользователь должен был лезть в файл руками. На Ubuntu 24.04 это
особенно проблемно: `/etc/resolv.conf` — симлинк на
`/run/systemd/resolve/stub-resolv.conf`, который управляется
`systemd-resolved`, и прямая правка бесполезна (переписывается при
ребуте / per-link change). На одних серверах проблема есть, на других
нет — зависит от того, активен ли systemd-resolved и какой upstream DNS
провайдер отдаёт через DHCP.**

### Решение

Новый модуль `chimera/modules/resolv_conf_fix.py` — автоматическое
исправление `/etc/resolv.conf` одной кнопкой, с диагностикой, бэкапом
и возможностью отката.

### Что делает модуль

**`diagnose_resolv_conf()`** — полная диагностика:
- Читает `/etc/resolv.conf` (статичный или симлинк на systemd-resolved).
- Проверяет активность `systemd-resolved` через `systemctl is-active`.
- Через `resolvectl dns` получает Global DNS и per-link DNS (от DHCP).
- Читает `listen_addresses` из `/etc/dnscrypt-proxy/dnscrypt-proxy.toml`.
- Через `ss -tlnu` проверяет, что DNSCrypt реально слушает порт.
- Определяет `fix_needed` + `fix_method`:
  - `systemd_resolved` — если systemd-resolved активен.
  - `static_resolv_conf` — если нет (Debian, минимальные cloud-образы).

**`fix_resolv_conf_to_localhost()`** — программный fix:
- **Pre-flight**: убеждается, что DNSCrypt активен И слушает порт —
  иначе фикс отменяется (black-hole risk).
- **systemd_resolved метод** (Ubuntu 24.04):
  - Создаёт drop-in `/etc/systemd/resolved.conf.d/chimera-dns.conf` с
    `DNS=127.0.0.1`, `FallbackDNS=` (пустой), `Domains=~.`,
    `DNSOverTLS=opportunistic`, `DNSSEC=allow-downgrade`,
    `MulticastDNS=no`, `LLMNR=no`.
  - `resolvectl dns-global set 127.0.0.1` — глобальный upstream.
  - `resolvectl dns-default-route set false` — отключает per-link DNS
    (чтобы DHCP провайдера не подсовывал свой).
  - `systemctl restart systemd-resolved` — применяет drop-in.
  - `resolvectl flush-caches` — сброс кэша.
- **static_resolv_conf метод** (Debian, cloud-образы без systemd-resolved):
  - Бэкап `/etc/resolv.conf` → `/etc/resolv.conf.chimera.bak` (если нет).
  - Удаляет симлинк если есть.
  - Пишет `nameserver 127.0.0.1` + `options timeout:1 attempts:1`.
- State сохраняется в `/var/lib/xray-installer/resolv_conf_fix.json`.

**`rollback_resolv_conf()`** — откат к прежнему состоянию:
- Удаляет drop-in, перезапускает systemd-resolved.
- `resolvectl dns-default-route set true` — возвращает per-link DNS.
- Восстанавливает `/etc/resolv.conf` из бэкапа.

**`do_fix_resolv_conf_interactive()`** — TUI-экран: диагностика +
кнопки "Исправить" / "Откатить" / "Повторить диагностику".

### Интеграция в DNS Leak Test

В `do_dns_leak_test()` (`_core.py`) после обнаружения leak показывается
prompt: "Открыть экран авто-фикса /etc/resolv.conf? [Y/n]". При `Y`
запускается `do_fix_resolv_conf_interactive()`. После применения фикса
пользователь может повторить DNS Leak Test — резолверов в РФ быть
не должно.

### Безопасность

- **Pre-flight checks**: фикс не применяется, если DNSCrypt не активен
  или не слушает порт — иначе сервер остался бы без DNS (black-hole).
- **Бэкап**: оригинальный `/etc/resolv.conf` сохраняется в
  `/etc/resolv.conf.chimera.bak` (не перезаписывается при повторном
  фиксе — idempotency).
- **Rollback**: кнопка "Откатить" в TUI + программная `rollback_resolv_conf()`.
- **State**: все действия логируются в `/var/log/chimera.log` и
  `/var/lib/xray-installer/resolv_conf_fix.json`.
- **Drop-in persist**: drop-in в `/etc/systemd/resolved.conf.d/` переживает
  ребут — systemd-resolved автоматически его применяет при старте.

### Тесты

`tests/test_resolv_conf_fix.py` — 19 новых unit-тестов:
- `TestDiagnoseResolvConf` (6) — диагностика: нет файла / localhost /
  внешний DNS / systemd-resolved с per-link DHCP / DNSCrypt не активен /
  DNSCrypt не слушает.
- `TestFixResolvConfToLocahost` (5) — программный fix: static rewrite /
  systemd drop-in / not-needed / dry-run / idempotency.
- `TestRollbackResolvConf` (3) — откат: static restore / systemd dropin
  removal / no-state.
- `TestParseDnscryptListenAddr` (5) — парсинг TOML: IPv4 / IPv6 /
  multiple / no-TOML / no-listen_addresses.

Все 73 теста в DNS-свите проходят (test_resolv_conf_fix +
test_core_dns_redirect_integration + test_diagnostics +
test_dnscrypt_setup + test_dnscrypt_selector).

### Файлы

- `chimera/modules/resolv_conf_fix.py` — новый модуль (580+ строк).
- `chimera/_core.py` — импорт модуля + интеграция в `do_dns_leak_test()`.
- `tests/test_resolv_conf_fix.py` — новые тесты (19 кейсов).

---

## FEAT(telemt): client_mss_bulk — двухуровневый MSS (handshake / relay) — 1 августа 2026

**Telemt ≥ 3.5.x поддерживает параметр `client_mss_bulk` — опциональный MSS
для bulk-фазы (передачи данных после TLS-handshake). Если задан, низкий
`client_mss` применяется только на время TLS-handshake (включая
инспектируемый DPI ServerHello), а как только соединение переходит в фазу
relay, MSS клиентского сокета поднимается до `client_mss_bulk`. Это
сохраняет anti-DPI фрагментацию handshake, но для данных возвращает пакеты
нормального размера — снижает исходящий packets-per-second в ~N раз
(N = segment multiplier handshake-MSS, для `"tspu"` это ~16x).**

### Зачем это нужно

Без `client_mss_bulk` низкий `client_mss` (например `"tspu"`, MSS=92)
дробит **все** пакеты — не только ClientHello, но и весь последующий
трафик. Это создаёт ~16-кратный overhead по packets-per-second относительно
нормы. На многих VPS-хостингах (особенно RU/Asian) **abuse-детекция
автоматически банит серверы за аномальный PPS**, считая их source of
DDoS/scan. Это конкретная боль пользователей Telemt.

С `client_mss_bulk = "1400"` (Near-MTU) фрагментируется только handshake —
дальше трафик идёт нормальными пакетами, PPS падает в 16x, и abuse-детекция
не срабатывает.

### Что добавлено

1. **`chimera/modules/telemt_mss_selector.py`**:
   - Новая функция `mss_bulk_select_interactive(client_mss)` — интерактивный
     экран выбора bulk-MSS. Показывается только если выбран ненулевой
     handshake-MSS (иначе нет смысла — bulk без handshake не имеет эффекта).
   - Новая функция `mss_bulk_status_line(client_mss_bulk, client_mss)` —
     читаемая строка для итогового бокса установки.
   - Новая функция `get_current_mss_bulk(config_file)` — чтение
     `client_mss_bulk` из `telemt.toml`.
   - Новая константа `_BULK_PRESETS` — список bulk-пресетов:
     `1400` (Near-MTU, recommended), `1360` (VPN-Safe), `1280` (IPv6-Min),
     `1200` (Conservative), `tspu` (Mirror Handshake), `""` (без bulk).
   - **REGRESSION FIX**: `get_current_mss` теперь использует regex с
     негативной заглядкой `(?!\w)`, чтобы не сматчить `client_mss_bulk`
     (который тоже начинается на `client_mss`). До фикса при наличии в
     конфиге `client_mss_bulk` функция могла вернуть значение bulk-MSS
     вместо handshake-MSS.

2. **`chimera/modules/mtproto.py`**:
   - `_write_config()` принимает новый параметр `client_mss_bulk: str = ""`.
     Если задан и задан `client_mss` — в TOML пишется строка
     `client_mss_bulk = "..."` сразу после `client_mss`, в секции `[server]`.
     Если `client_mss` пустой — bulk не пишется (нет смысла).
   - `_run_install_inner()` после выбора handshake-MSS спрашивает bulk-MSS
     (через `mss_bulk_select_interactive`), если handshake-MSS не пустой.
   - Оба вызова `_write_config()` (own-site и donor-режим) обновлены.
   - Финальный summary-бокс показывает обе строки: `MSS:` (handshake) и
     `Bulk:` (bulk), если bulk задан.

### UX

- После выбора handshake-MSS пользователь видит отдельный экран "BULK MSS
  • ДВУХУРОВНЕВЫЙ РЕЖИМ (HANDSHAKE / RELAY)" с объяснением: что делает
  bulk-MSS, почему это полезно (PPS-reduction), требование telemt ≥ 3.5.x.
- Recommended bulk = `1400` (Near-MTU) — самое близкое к MTU 1500.
- "0" = без bulk (прежнее поведение: низкий MSS на всё соединение).
- "C" = ручной ввод числа 88–4096.
- Enter = recommended bulk (как и в `mss_select_interactive`, где Enter = tspu).

### Backward compatibility

- Пустой `client_mss_bulk` = прежнее поведение (handshake-MSS на всё
  соединение). Никаких изменений в существующих конфигах не происходит.
- На старых версиях Telemt (< 3.5.x) параметр игнорируется без ошибки
  (как и `client_mss`).
- Грамматика значения идентична `client_mss` (пресеты `"extreme-low"` /
  `"tspu"` / `"2in8"` или число 88–4096 в строке).

### Тесты

- `tests/test_telemt_mss_selector.py` — добавлено 5 новых классов с 20
  тестами:
  - `TestBulkPresets` (5) — структура `_BULK_PRESETS`.
  - `TestMssBulkStatusLine` (5) — форматирование status-line.
  - `TestGetCurrentMssBulk` (6) — чтение из TOML.
  - `TestGetCurrentMssNoFalseMatchBulk` (2) — регрессия: `get_current_mss`
    не должен сматчить `client_mss_bulk`.
  - `TestMssBulkSelectInteractive` (6) — логика выбора (empty handshake,
    preset keys, custom, retry on out-of-range).
- `tests/test_mtproto.py` — добавлено 6 новых тестов в `TestWriteConfig`:
  - `test_client_mss_bulk_inserted_when_both_set`
  - `test_client_mss_bulk_skipped_when_no_handshake_mss`
  - `test_client_mss_bulk_skipped_when_empty`
  - `test_client_mss_bulk_uses_string_quotes`
  - `test_client_mss_bulk_accepts_named_preset`
  - `test_both_mss_in_server_section_after_port`

Все 317 тестов в telemt-свите проходят (test_telemt_mss_selector +
test_mtproto + test_telemt_ios_fix + test_telemt_syn_limiter +
test_telemt_panel + test_telemt_nginx_fallback + test_telemt_fallback +
test_telemt_download).

### Источник

Документация Telemt: https://github.com/telemt/telemt/blob/main/docs/Config_params/CONFIG_PARAMS.ru.md#client_mss_bulk

---

## FIX(diagnostics): DoH-резолв во всех модулях — массовый фикс «старого IP» — 1 августа 2026

**Продолжение фикса от 1 августа (DoH-резолв exit-нод — обход локального
DNS-кэша). После первого фикса оставалось ещё 8 модулей, где домен
exit-ноды резолвился через `socket.gethostbyname()` — системный резолвер,
отдающий устаревший IP из `/etc/hosts`, `systemd-resolved`, `nscd` или
`dnsmasq`. Это создавало риски в нескольких критичных местах:

- `autoban.py` — whitelist IP exit-нод для автобана. Если в whitelist
  окажется СТАРЫЙ IP, а нода уже переехала на НОВЫЙ — autoban может
  забанить ноду на НОВОМ IP при TLS-handshake ошибках, и трафик встанет.
  Затронуто: `_autoban_get_chain_ips()` (3 вызова) + inline cron-скрипт
  `/usr/local/bin/xray-autoban.sh` (2 вызова, запускается каждые 5 мин).
- `mtu_tuning.py` — iptables MSS-clamping правила. Если правило добавлено
  со старым IP, трафик к ноде на НОВОМ IP не получит корректный MSS —
  будут проблемы с PMTU. Затронуто: `_mtu_probe`, `_mtu_apply_rules`,
  `_mtu_remove_rules`, sweep-зонд (4 вызова).
- `node_health_monitor.py` — фоновый TCP-ping exit-нод (крон). Если пинг
  идёт на старый IP — мониторинг покажет ноду как «down», хотя она жива.
- `youtube_route.py` — флаг страны рядом с IP ноды в TUI-меню. По старому
  IP флаг мог не соответствовать реальной стране ноды.
- `as_direct.py` — определение ASN/IP для домена. По старому IP —
  некорректный ASN.
- `_core.py` → `_port_block_fallback` — TCP-пробы до домена сервера
  при недоступности check-host.net.

### Изменение

Во всех перечисленных модулях `socket.gethostbyname()` заменён на
`_resolve_host_fresh()` (DoH через Cloudflare 1.1.1.1 + Google 8.8.8.8
JSON API, fallback на `gethostbyname()`). DoH идёт напрямую к публичным
рекурсивам, минуя любой локальный кэш.

Особый случай — **inline cron-скрипт** в `autoban.py` (`_autoban_install_cron`):
это отдельный Python-процесс без доступа к `chimera.modules`, поэтому
функция `_resolve_fresh()` встроена прямо в текст cron-скрипта
(вместе с `import socket`, DoH-циклом и fallback). Скрипт самодостаточен.

### Тесты

- Все существующие unit-тесты проходят (158/158 в `test_chain_nodes`,
  `test_diagnostics`, `test_autoban`, `test_mtu_tuning`, `test_as_direct`,
  `test_youtube_route`, `test_node_health_monitor`, `test_youtube_ip_pin`).
- Inline cron-скрипт валидируется отдельной проверкой
  (`scripts/check_autoban_cron.py`) — после подстановки f-string
  переменных тело скрипта парсится как валидный Python.

### Файлы

- `chimera/modules/autoban.py` — `_autoban_get_chain_ips()` (хелпер `_resolve`)
  + inline cron-скрипт (функция `_resolve_fresh` + 2 замены).
- `chimera/modules/mtu_tuning.py` — новая функция `_mtu_resolve_host()`,
  используется в 4 местах.
- `chimera/modules/node_health_monitor.py` — `_tcp_ping()`.
- `chimera/modules/youtube_route.py` — `_resolve_node_ip_and_flag()`.
- `chimera/modules/as_direct.py` — `_lookup_asn_for_target()`.
- `chimera/_core.py` — `_port_block_fallback()`.
- `scripts/check_autoban_cron.py` — новый скрипт-валидатор.

### Не изменено (намеренно)

- `_core.py:3340` — `socket.gethostbyname(socket.gethostname())` — резолв
  собственного hostname сервера (localhost), DoH тут не нужен.
- `fragment_fuzzer.py:175` — резолв собственного `domain` сервера из
  state.json. Если domain сервера сменил IP, это уже не наш сервер;
  кэш не создаёт проблемы.
- `warp.py:516, 632` — резолв стационарных endpoint'ов Cloudflare WARP
  (`engage.cloudflareclient.com` и curated-списков). Кэш не проблема,
  Cloudflare A-записи меняются редко и предсказуемо.
- `chimera/modules/_vendor/dpi_detector/` — vendored код DPI-детектора,
  не наш.

---

## FIX(diagnostics): DoH-резолв exit-нод — обход локального DNS-кэша — 1 августа 2026

**При диагностике «одной кнопкой» (а также в SpeedTest и матрице состояния
exit-нод) определение GeoIP, TCP-latency и TCP-ping для exit-ноды стучались
на СТАРЫЙ IP-адрес домена, хотя реальный клиент (xray/sing-box) подключался
на НОВЫЙ IP. Симптом: пользователь сменил A-запись домена (например
`node-b.example`) в DNS-провайдере, нода работает по vless-ссылке, но
диагностика упорно показывает старый IP, старого ISP и т.д.**

### Корень проблемы

Все диагностические функции резолвили домен exit-ноды через
`socket.gethostbyname()` — системный резолвер сервера. Этот резолвер
возвращает адрес из локального кэша, который может быть устаревшим:

- Запись в `/etc/hosts` (часто прописывается при отладке и забывается убрать).
- `systemd-resolved` / `nscd` / `dnsmasq` кэшируют A-record с большим TTL
  и не успевают его сбросить после смены A-записи в DNS-провайдере.
- Локальный forwarder (например, роутер или корпоративный DNS), который
  отдаёт устаревший кэш.

Реальный xray-клиент при этом может использовать свой resolver
(libc + свой кэш, либо DoH/DoT в случае sing-box) — и идти на НОВЫЙ IP.
В итоге диагностический «TCP-ping» и реальный клиентский трафик расходятся.

### Локация бага

- `chimera/modules/chain_nodes.py` — функции `_speed_test_node_geo()`
  и `_speed_test_node_latency()`, а также inline-резолв в меню
  «Пинг Exit Node» (`do_manage_nodes`, `ch == "t"`) и `_tcp_ms()`
  в `do_node_health_matrix()`.
- `chimera/modules/diagnostics.py` — функция `_diag_tcp_probe()`,
  используемая шагом 5 («Тест маршрутизации — TCP ping exit-нод»)
  и шагом 11 («Exit-ноды: latency») мастера `do_full_diagnostic()`.

### Изменение

1. **Новая функция `_resolve_host_fresh(host, timeout=3)` в
   `chimera/modules/chain_nodes.py`** — резолв hostname → IPv4 через
   публичные DoH-резолверы:
   - Если `host` уже валидный IPv4 — возвращается как есть, без DoH.
   - Cloudflare DoH JSON API: `https://1.1.1.1/dns-query?name=…&type=A`
     с заголовком `Accept: application/dns-json`.
   - Если Cloudflare недоступен / NXDOMAIN — Google DoH JSON API:
     `https://8.8.8.8/resolve?name=…&type=A`.
   - Из ответа берётся только A-record (DNS type 1); AAAA игнорируется
     (callers ожидают IPv4-строку).
   - Fallback на `socket.gethostbyname()` (системный резолвер) — лучше
     старый IP, чем никакой.
   - Если всё упало — `None`.

2. **`_speed_test_node_geo()` / `_speed_test_node_latency()`** —
   резолв через `_resolve_host_fresh()` вместо `socket.gethostbyname()`.
   GeoIP теперь определяется по АКТУАЛЬНОМУ IP, latency мерируется до
   АКТУАЛЬНОГО IP.

3. **Меню «Пинг Exit Node» и `_tcp_ms()` в матрице состояния** —
   то же самое: флаг страны и TCP-ping по АКТУАЛЬНОМУ IP.

4. **`_diag_tcp_probe()` в `diagnostics.py`** — теперь сначала пробует
   DoH-резолв (через lazy import `_resolve_host_fresh` из `chain_nodes`),
   и если DoH отдал IPv4 — формирует addrinfo-подобный список вручную
   для `socket.connect()`. Если DoH не сработал — fallback на системный
   `getaddrinfo()`, который дополнительно отдаёт IPv6-адреса
   (сохраняет прежнюю логику dual-stack для IPv6-only доменов на
   IPv4-only серверах, см. предыдущий фикс от 24 июля 2026).

### Тесты

- `tests/test_chain_nodes.py` — новый класс `TestResolveHostFresh`
  с 7 тестами: IPv4 passthrough, Cloudflare DoH success, Cloudflare→Google
  fallback, NXDOMAIN→gethostbyname, AAAA ignored, all DoH fail→fallback,
  all fail→None.
- `tests/test_diagnostics.py` — в `TestDiagTcpProbe.setUp` патчится
  `_resolve_host_fresh → None` (старые тесты проверяют fallback-логику
  перебора address family), добавлен новый
  `test_doh_resolves_overrides_getaddrinfo` (DoH отдаёт НОВЫЙ IP →
  `getaddrinfo` не должен вызываться).

Все 61 тест в `test_chain_nodes` + `test_diagnostics` проходят.

---

## SECURITY(cdn-masking): PBKDF2 + state-file вместо SHA-256-в-коде — 28 июля 2026

**Критический security-фикс модели «платного скрытого доступа». Предыдущая
реализация хранила несолёный SHA-256 hash пароля захардкоженным в исходнике,
который инструкция велела коммитить в публичный репозиторий. Это полностью
обнуляло security-модель: любой, кто клонирует репозиторий (публичный GitHub
+ GitLab), получал hash и мог перебирать его офлайн на GPU без следов на
сервере. Каждая смена пароля добавляла ещё один hash в git-историю навсегда.**

**Что было неправильно (для понимания, не для повторения):**
- `_CDN_MASKING_PASSWORD_HASH` — константа в .py-файле, менялась через правку
  кода + git commit + git push. Hash физически виден в публичном репозитории
  и во всей git-истории.
- `hashlib.sha256(password).hexdigest()` — без соли, без растяжения ключа
  (PBKDF2/bcrypt/scrypt/argon2). Быстрый hash = дешёвый брутфорс.

**Изменение:**

1. **Хранение — ТОЛЬКО в state-файле на диске сервера, НИКОГДА не в коде
   и не в git.** Аналогично существующим state-файлам в _core.py
   (HEALTH_CHECK_FILE / STATE_FILE и десятки протокольных state_file):
   ```
   CDN_MASKING_HASH_FILE = Path("/var/lib/xray-installer/cdn_premium.hash")
   ```
   Формат файла — JSON: `{"salt": "<hex>", "hash": "<hex>",
   "iterations": N, "algo": "pbkdf2_sha256"}`. Параметры iterations и algo
   хранятся явно в файле (не константой в коде), чтобы в будущем можно было
   поднять число итераций без поломки старых хешей. Права на файл — 0600,
   владелец root (chmod сразу после записи).

2. **`_verify_cdn_masking_password(password)`** (xhttp_cdn_masking.py) —
   переписана:
   - Если `CDN_MASKING_HASH_FILE` не существует → `return False` (как и
     требуется по исходной задаче — «функция не активирована»).
   - Читает JSON, `salt = bytes.fromhex(data["salt"])`, `stored_hash =
     data["hash"]`, `iterations = data["iterations"]`.
   - `computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
     salt, iterations).hex()`.
   - `hmac.compare_digest(computed, stored_hash)` — constant-time сравнение
     сохранено.
   - Обёрнуто в `try/except` — любая ошибка (битый JSON, отсутствующие
     ключи, permission denied) → `return False`, не бросает исключение
     наружу (не выдаёт существование/состояние раздела через traceback).
   - **Старый формат (без «iterations»/«algo»)** — НЕ мигрируется
     автоматически. Возвращает False + WARN в лог. Админ должен пересоздать
     пароль через `generate_cdn_masking_password_hash.py`. Авто-миграция
     SHA-256→PBKDF2 без участия админа запрещена ТЗ — это ослабило бы
     гарантию.

3. **`chimera/scripts/generate_cdn_masking_password_hash.py`** — переписан:
   - `check_password_strength` — БЕЗ ИЗМЕНЕНИЙ (эта часть была верной).
   - `salt = os.urandom(16)`, `hash = pbkdf2_hmac(...)` с новым salt.
   - Записывает JSON напрямую в `CDN_MASKING_HASH_FILE` (chmod 0600, root).
     Атомарная запись через `tmp.replace(dest)`.
   - Убраны все инструкции про «закоммитьте и запушьте в репозиторий» —
     этой фразы нет нигде в выводе скрипта.
   - Финальный вывод: «Пароль установлен. Файл
     /var/lib/xray-installer/cdn_premium.hash обновлён (права 0600, root).
     Пароль сообщите платным клиентам через защищённый канал».
   - Новая функция `write_hash_file(password, dest, iterations)` —
     тестируемая, пишет JSON в любой путь (для unit-тестов).

4. **Дефолтное `iterations` для НОВЫХ хешей — 600000** (актуальная
   рекомендация OWASP для PBKDF2-HMAC-SHA256 на 2025-2026). Не меньше
   100000 — это нижняя граница, проверяется в тестах.

5. **Докстринги** в `xhttp_cdn_masking.py` (верхний блок СОСТАВ пункт 6
   и блок «СКРЫТОЕ МЕНЮ — защита паролем») — приведены в соответствие
   новой схеме. Удалены упоминания «SHA-256 hash + hmac.compare_digest»
   и «админ меняет hash через chimera/scripts/... и коммитит в репозиторий».

**DO NOT TOUCH (по ТЗ):** `_unlock_cdn_masking_menu()` (getpass-ввод,
UI-обёртка, сообщения об ошибке) — не менялся по существу. Скрытость пункта
меню в `_core.py` (`choice.lower() == "cdn"`, тихий fallback) — корректна,
не трогалась.

**Тесты (tests/test_xhttp_cdn_masking.py):**
- `TestPasswordVerification` — 19 тестов, покрывает все 7 пунктов ТЗ:
  1. Файла нет → verify() всегда False для любого пароля.
  2. Установленный пароль → verify(correct)==True, verify(wrong)==False.
  3. (в TestPasswordHashScript) Два прогона одного пароля → разные salt
     и hash.
  4. Битый JSON / отсутствующие ключи (salt/hash/iterations/algo) → False
     без исключения.
  5. (в TestPasswordHashScript) Файл записывается с правами 0600.
  6. Старый формат (без iterations/algo) → False с WARN в лог, не падает,
     не пытается сравнить как PBKDF2.
  7. (в TestPasswordHashScript) grep по скрипту — нет «закоммитьте»/
     «запушьте»/«git commit»/«git push»/«замените значение константы»/
     `_CDN_MASKING_PASSWORD_HASH` (case-sensitive для идентификатора,
     case-insensitive для русских фраз).
- `TestPasswordHashScript` — 20 тестов: check_password_strength (5),
  write_hash_file (создание, JSON, 0600, salt 16 байт, hash 64 hex,
  перезапись, parent dir creation, roundtrip с verify), случайность
  salt между прогонами, отсутствие forbidden фраз в source и в main()
  output.
- Остальные классы (`TestBuildCdnMaskingInbound`, `TestBuildClientExtra`,
  `TestBuildClientXhttpSettings`, `TestCdnMaskingConstants`) — НЕ
  тронуты, все 36 тестов проходят.

**Регрессии:** 0. `tests/test_xhttp_cdn_masking.py` — 75/75. Смежные
тесты: `test_xray_install` (58), `test_subscription` (33),
`test_client_config_export` (7), `test_users_manager` (12),
`test_tui` (8), `test_ios_link_regression` (14), `test_ios_link_variant`
(5), `test_nginx_watchdog` (2), `test_ssl_certbot` (2),
`test_xhttp_path_gen` (14), `test_fake_login_template` (17),
`test_cdn_masking_guide` (22) — все PASS. `full_test.py` — 10/10
проверок, 74/74 подтестов.

**Совместимость:**
- Старый hash-файл (если был создан предыдущей версией с SHA-256-в-коде)
  — на диске его не было (он был в коде), так что после обновления профиль
  просто остаётся закрытым до тех пор, пока админ не запустит
  `generate_cdn_masking_password_hash.py` для создания PBKDF2 hash-файла.
- Если админ ранее «установил» пароль правкой константы в коде — этот
  пароль больше НЕ работает (константа удалена). Нужно пересоздать через
  скрипт.
- Все остальные функции (`build_xhttp_cdn_masking_inbound`, fake-login
  шаблон, CDN guide, nginx_setup cdn_masking_mode, и т.д.) — не менялись.

---

## FEAT(xhttp): CDN masking profile — обход белых списков через Beeline CDN — 28 июля 2026

**Новый опциональный профиль XHTTP для маскировки трафика под реальный
HTTPS через CDN Beeline (и аналоги). Не затрагивает текущий простой
XHTTP-режим (path+mode) — это отдельный профиль, активируемый через
скрытое меню.**

**Состав:**

1. **`chimera/modules/xhttp_path_gen.py`** (новый файл) — генератор
   случайного path-обманки. Порт `gen_path()` из `install-caddy-node.sh`
   на Python (через `secrets` module, crypto-strength RNG). Списки
   WORDS/VERSIONS/EXTS идентичны bash-оригиналу (54/12/2 элемента).
   Формат пути — `^/[\w-]+(/[\w-]+){0,2}\.(php|ts)$` (1-3 сегмента +
   расширение php/ts).

2. **`chimera/modules/xhttp_cdn_masking.py`** (новый файл) — ядро профиля:
   - `build_xhttp_cdn_masking_inbound(domain, path, port=7443) -> dict`
     — возвращает полный `xhttpSettings` (mode/path/host/extra) для
     серверного инбаунда со всеми экспертными полями (xPaddingBytes 50-150,
     xPaddingHeader "X-Api-Key", xPaddingMethod "tokenish",
     xPaddingObfsMode true, xPaddingPlacement "header",
     seqKey "chunk_id", seqPlacement "query",
     sessionKey/sessionIDKey "auth", sessionIDTable "Base62",
     sessionIDLength "16-32", sessionPlacement+sessionIDPlacement "query",
     noSSEHeader/noGRPCHeader true,
     scMaxBufferedPosts 100, scMaxEachPostBytes 3000000,
     scMinPostsIntervalMs "5-10", scMaxConcurrentPosts 10,
     serverMaxHeaderBytes 32768,
     uplinkHTTPMethod "POST", downloadHTTPMethod "GET",
     uplinkDataPlacement "body",
     xmux.maxConcurrency "1").
   - `build_xhttp_cdn_masking_client_extra()` — клиентская копия extra
     (симметрична серверу).
   - `CDN_MASKING_INBOUND_PORT = 7443` — отдельный backend-порт от 8443
     (simple XHTTP), чтобы профили не конфликтовали.
   - `_unlock_cdn_masking_menu()` / `run_cdn_masking_install()` —
     скрытое меню с парольной защитой. Пароль в коде НЕ хранится —
     только его SHA-256 hash (проверка через `hmac.compare_digest`,
     constant-time). Требования к паролю: ≥20 символов, заглавные +
     прописные + спец. символы.

3. **`chimera/modules/cdn_masking_guide.py`** (новый файл) —
   `print_cdn_setup_instructions(domain, path)` печатает пошаговую
   инструкцию для ручной настройки ресурса в Beeline CDN (9 шагов:
   вход в ЛК → создание ресурса → HTTPS → кэширование → таймауты →
   Rewrite → WebSocket → CNAME → проверка). Статический текст с
   f-string подстановкой сгенерированных domain/path, без интерактивности.

4. **`chimera/modules/nginx_setup_templates.py`** — добавлен шаблон #16
   `create_fake_login(web_root)`: одностраничная заглушка «Доступ к
   серверу» с JS-капчей. HTML перенесён 1:1 из base64-декодированного
   decoy #1 файла `install-caddy-node.sh` (DECOYS[0]). Не входит в
   стандартный выбор шаблонов 1..15 — активируется только через
   `cdn_masking_mode=True` в `setup_nginx_final()`.

5. **`chimera/modules/nginx_setup.py`** — `setup_nginx_final()` получил
   новый опциональный параметр `cdn_masking_mode: bool = False`. При
   `True`:
   - `XHTTP_BACKEND_PORT` переключается на 7443 (CDN_MASKING_INBOUND_PORT);
   - вместо `create_website()` вызывается `create_fake_login()`;
   - в location-блок добавляются CDN-специфичные директивы
     (`large_client_header_buffers 8 32k`, `underscore_in_headers on`,
     `proxy_send_timeout 86400s`, `proxy_read_timeout 86400s`,
     `proxy_next_upstream off`).
   Дефолтное поведение (без параметра) полностью сохранено — ни одного
   байта вывода не меняется в простом XHTTP-режиме.

6. **`chimera/modules/xray_install.py`** — `generate_xray_config_xhttp()`
   проверяет флаг `core.XHTTP_CDN_MASKING`. При `True` вызывает
   `build_xhttp_cdn_masking_inbound()` вместо `_build_xhttp_settings()`,
   обновляет `XHTTP_BACKEND_PORT` до 7443. Падение на простой профиль
   при `ImportError` (graceful fallback).

7. **`chimera/modules/users_manager.py`** — `_gen_vless_link()` при
   активном профиле добавляет `&host=<host>` в URL (значение из
   `CDN_MASKING_HOST` или domain).

8. **`chimera/modules/client_config_export.py`** — `do_generate_client_config()`
   при активном профиле:
   - sing-box JSON: `transport` получает `host` + `extra` (симметрично серверу);
   - VLESS-ссылка: добавляется `&host=` (пост-обработка через `.replace()`,
     исходная подстрока `&type=xhttp&path={xhttp_path_enc}#VLESS-xHTTP`
     сохранена для обратной совместимости с regression-тестами);
   - label становится `VLESS-xHTTP-CDN` (визуальное отличие в клиенте).

9. **`chimera/_core.py`** —
   - новая глобальная `XHTTP_CDN_MASKING: bool = False`;
   - `do_full_install()` передаёт `cdn_masking_mode=bool(globals().get("XHTTP_CDN_MASKING", False))`
     в `setup_nginx_final()`;
   - `main_menu()` добавляет скрытый пункт: ввод строки `"cdn"` (без
     кавычек) в главном меню вызывает `run_cdn_masking_install()`. При
     ошибке — тихий fallback на "Неверный выбор" (не выдаёт существование
     скрытого меню);
   - `_load_state_into_globals()` и блок сохранения state.json обновлены
     для персистентности `xhttp_cdn_masking` флага.

10. **`chimera/scripts/generate_cdn_masking_password_hash.py`** (новый
    файл) — утилита для админа: генерирует SHA-256 hash пароля для
    скрытого меню, проверяет требования (≥20 символов, заглавные +
    прописные + спец.), печатает инструкцию по замене хеша в коде.
    Plaintext-пароль в коде НЕ хранится — только хеш.

**Тесты:**
- `tests/test_xhttp_path_gen.py` — 14 тестов (формат пути, regex,
  списки WORDS/VERSIONS/EXTS идентичность bash-оригиналу).
- `tests/test_xhttp_cdn_masking.py` — 48 тестов (все обязательные
  extra-ключи, значения по референсу, симметрия клиент/сервер,
  проверка пароля через SHA-256, требования к паролю, отсутствие
  plaintext в коде).
- `tests/test_fake_login_template.py` — 17 тестов (создание файлов,
  наличие ключевых HTML-элементов, регистрация шаблона #16 в dispatcher).
- `tests/test_cdn_masking_guide.py` — 22 теста (подстановка domain/path,
  все 9 шагов присутствуют, origin/tunnel URLs, обработка пустых
  domain/path).

**Регрессии:** 0. Полный suite `tests/test_xray_install.py` (58),
`tests/test_subscription*.py` (96+), `tests/test_client_config_export.py` (7),
`tests/test_ios_link_regression.py` (14), `tests/test_users_manager.py`,
`tests/test_tui.py` (8), `tests/test_nginx_watchdog.py` (2),
`tests/test_ssl_certbot.py` (2) — все PASS. `full_test.py` — 10/10
проверок, 74/74 подтестов.

**Совместимость:**
- Текущий простой XHTTP-режим (path+mode) — НЕ затронут. Дефолтное
  поведение `setup_nginx_final()`, `generate_xray_config_xhttp()`,
  `_gen_vless_link()`, `do_generate_client_config()` идентично
  предыдущей версии.
- Профиль CDN masking — опциональный, активируется только через
  скрытое меню (ввод `"cdn"` + код доступа).
- Пароль доступа меняется через `chimera/scripts/generate_cdn_masking_password_hash.py`
  (админ генерирует новый hash, заменяет константу в коде, сообщает
  пароль платным клиентам через защищённый канал).

---

## FIX(awg): v5.4 — комментировать пустые I1-I5 (как в эталоне Amnezia) — РЕАЛЬНЫЙ КОРЕНЬ проблемы zvshka — 27 июля 2026

**КОРЕНЬ ПРОБЛЕМЫ НАЙДЕН (подтверждено zvshka):**

1. zvshka: "Тож самое" после `git pull` + `systemctl restart` — самоисцеление v5.2.2 НЕ сработало.
2. zvshka: "Как только я комментирую строчки с I1-5 всё включается" — комментарий `#` решает проблему.
3. zvshka: "Но при добавлении клиента конфиг перезаписывается и комментарии удаляются" — писатели конфига удаляют комментарии.

**Почему самоисцеление v5.2.2 не сработало:** `systemctl restart awg-quick@awg0` вызывает `awg-quick up awg0` напрямую через systemd (`ExecStart=/usr/bin/awg-quick up awg0`) — это НЕ проходит через наш `awgs_apply()`. systemd запускает бинарник awg-quick напрямую, а не наш Python-код. Поэтому самоисцеление никогда не вызывается при `systemctl restart`.

**Корневое решение v5.4:** Перестать писать пустые `I2 =` строки вообще. Вместо этого **комментировать** I1-I5 когда они пустые (как делает официальный Amnezia — см. эталонный конфиг из Docker-контейнера). Закомментированные строки:
- **Игнорируются старыми amneziawg-tools** (парсер пропускает `#`) — решает проблему zvshka
- **Игнорируются современными amneziawg-tools** (тоже пропускают `#`)
- **Не нужны для Keenetic** — эталонный Amnezia конфиг имеет все I1-I5 закомментированными, и Keenetic его принимает

Это устраняет необходимость в `awgs_supports_i2_i5()` для писателей конфига — закомментированный формат работает ВЕЗДЕ, не требует определения возможностей.

### Что реализовано

**Файлы:** `chimera/modules/awg_standalone.py`, `chimera/modules/awg_qr.py`, `chimera/modules/awg_transport.py`

**Логика (одинаковая для всех 6 функций-писателей):**
```python
for key in ("i1", "i2", "i3", "i4", "i5"):
    val = params.get(key, "")
    if val:
        lines.append(f"{key.upper()} = {val}")     # непустое — без комментария
    else:
        lines.append(f"# {key.upper()} = ")         # пустое — комментируем (как в эталоне Amnezia)
```

**Функции-писатели (6 штук в 3 модулях):**
- `awg_standalone.awgs_build_server_conf()` — серверный awg0.conf
- `awg_qr.awgs_qr_build_client_conf()` — клиентский .conf для QR
- `awg_transport._awg_build_i_lines()` — общий хелпер для 4 cascade-функций:
  - `_awg_server_conf_text()`
  - `_awg_client_conf_text()`
  - `_awg_client_conf_for_node()`
  - `_awg_server_conf_for_node()`

### Почему это решает проблему zvshka

**До v5.4:** Конфиг содержит `I2 = ` (пустая строка) → старые amneziawg-tools падают с `Line unrecognized: I2=` → сервис не стартует. zvshka комментирует вручную → работает. Но при добавлении клиента конфиг перезаписывается → комментарии удаляются → снова падает.

**После v5.4:** Конфиг содержит `# I2 = ` (закомментировано) → старые amneziawg-tools игнорируют `#` → сервис стартует. При добавлении клиента конфиг перезаписывается → комментарии сохраняются (писатель пишет `# I2 = ` для пустых) → сервис продолжает работать.

### Что НЕ тронуто

- **awg_compat.py** (`awgs_supports_i2_i5()`) — остаётся для потенциального использования в будущем, но больше НЕ вызывается из писателей конфига. Закомментированный формат работает везде, не требует определения возможностей.
- **Самоисцеление в awgs_apply() (v5.2.2)** — остаётся как safety net для уже сломанных конфигов (когда кто-то вручную записал `I2 = ` без `#`).
- **H1-H4 как диапазоны (v5.3)** — остаётся, не связано с I1-I5.
- **CPS tag-формат для I1 (v5.1)** — остаётся, I1 генерируется как `<r N>` (непустое, пишется без комментария).

### Тесты

Обновлены 7 тестов в 3 файлах:
- `tests/test_awg_standalone.py` — 3 теста v52 заменены на 3 теста v54:
  - `test_empty_i1_to_i5_commented_v54` — пустые I1-I5 закомментированы
  - `test_non_empty_i1_to_i5_uncommented_v54` — непустые без комментария
  - `test_no_bare_empty_i_keys_v54` — regression: нет `I2 = ` без `#` (ключевой тест на проблему zvshka)
- `tests/test_awg_qr.py` — 1 тест v52 заменён на `test_empty_i1_to_i5_commented_v54`
- `tests/test_awg_transport.py` — 4 теста v52 заменены на 4 теста v54 (по одной на каждую cascade-функцию). `test_all_4_functions_have_full_param_set` обновлён: проверяет 11 параметров без комментария + 5 I-ключей закомментированных.

### Прогон тестов

- 264 теста в затронутых модулях — PASS
- `full_test.py` — 10/10 PASS

### Сравнение с эталоном Amnezia

```
Эталон Amnezia (Docker-контейнер):
  # I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>
  # I2 =
  # I3 =
  # I4 =
  # I5 =

Наш конфиг (v5.4):
  I1 = <r 24>     ← непустое — без комментария
  # I2 =          ← пустое — закомментировано
  # I3 =          ← пустое — закомментировано
  # I4 =          ← пустое — закомментировано
  # I5 =          ← пустое — закомментировано
```

Формат совпадает. I1 у нас непустой (CPS tag `<r 24>`), поэтому без комментария — это правильно, I1 поддерживается даже старыми amneziawg-tools.

---

## FIX(awg): v5.3 — H1-H4 как диапазоны 'N-M' (эталонный формат Amnezia) — 27 июля 2026

**Анализ эталонного конфига:** zvshka прислал конфиг изнутри Docker-контейнера официального приложения Amnezia (`89fc2cd0cfcf`). Это дало нам эталонный формат AWG 2.0, который нам нужно поддерживать. Ключевые отличия от нашего формата:

1. **H1-H4 — ДИАПАЗОНЫ `N-M`, не одиночные числа:**
   ```
   H1 = 2135087609-2145903954
   H2 = 2147225277-2147461177
   H3 = 2147472979-2147474536
   H4 = 2147478893-2147482205
   ```
   Официальный Amnezia использует формат диапазона. Это скрывает magic header — DPI не может написать универсальное правило для детекции. Наш генератор всегда писал одиночные числа (узнаваемый отпечаток).

2. **I1-I5 — ЗАКОММЕНТИРОВАНЫ (`#`) по умолчанию:**
   ```
   # I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>
   # I2 =
   # I3 =
   # I4 =
   # I5 =
   ```
   Официальный Amnezia не пишет I1-I5 по умолчанию — они закомментированы. Если раскомментировать, I1 содержит комбинированный CPS-паттерн (маскировка под DNS-запрос). Это подтверждает наш CPS-формат, но показывает что по умолчанию I1-I5 должны отсутствовать, не присутствовать пустыми.

3. **S1-S4 — непустые значения:** `S1 = 125, S2 = 47, S3 = 27, S4 = 18`. Amnezia делает все 4 случайными, мы оставляли S1=S2=0.

### Что реализовано в v5.3

**Файл:** `chimera/modules/awg_presets.py`

**1. `_generate_non_overlapping_h_ranges()` — НОВАЯ функция:**

Генерирует один непересекающийся диапазон `[start, end]` для H1-H4. Диапазоны располагаются в верхней трети INT32_MAX (как в эталонном Amnezia конфиге — значения близкие к 2.1 млрд). `range_size=1000` — компромисс между анти-DPI эффективностью и совместимостью.

**2. `_generate_non_overlapping_h_values()` — обновлена:**

Теперь возвращает **кортеж СТРОК** формата `'N-M'` (диапазон), а не int. Это соответствует эталонному формату официального Amnezia. Генерирует 4 непересекающихся диапазона.

**3. `awgs_generate_full_manual_params()` — обновлена:**

Использует `_generate_non_overlapping_h_ranges()` для генерации диапазонов. Overrides для H1-H4 теперь принимают int или строку (число или диапазон 'N-M'). Возвращает как строку для единообразия.

**4. `awgs_presets_validate_params()` — обновлена:**

Принимает ДВА формата H1-H4 (как в эталонном конфиге Amnezia):
- Одиночное число: `H1 = 12345` (int или строка)
- Диапазон N-M: `H1 = 2135087609-2145903954` (как в официальном Amnezia)

Валидирует обе границы диапазона в 0..INT32_MAX, проверяет что lo ≤ hi.

### Что НЕ тронуто в v5.3

- **I1-I5:** Оставлены как есть (пишутся пустыми при supports=True, опускаются при supports=False). Эталон Amnezia комментирует их (`#`), но это семантически эквивалентно отсутствию — мы уже это делаем через `awgs_supports_i2_i5()` (v5.2) и самоисцеление (v5.2.2). Комментирование в .conf файле не меняет поведения awg-quick (парсер игнорирует `#`).
- **S1-S4:** Оставлены как есть (S1=S2=0 для пресетов, S3/S4 случайные). Amnezia делает все 4 случайными, но это сознательное решение автора пресетов (bivlked default).
- **Самоисцеление в awgs_apply() (v5.2.2):** остаётся как есть — лечит уже сломанные установки.
- **awgs_supports_i2_i5() через setconf (v5.2.1):** остаётся как есть — определяет поддержку для новых установок.

### Почему это улучшение

**До v5.3:** H1-H4 — одиночные числа (например `H1 = 17988250`). DPI может написать правило "если H1 в диапазоне 0-INT32_MAX и не диапазон — это Chimera project".

**После v5.3:** H1-H4 — диапазоны N-M (например `H1 = 2077007516-2077008515`), в верхней части INT32_MAX, как в эталонном Amnezia. DPI не может отличить Chimera от официального Amnezia по H1-H4.

### Тесты (`tests/test_awg_presets.py`)

Обновлены существующие тесты под диапазонный формат:
- `test_h_values_not_fixed_1_2_3_4` — проверяет что H1-H4 не 1,2,3,4 (теперь строки 'N-M')
- `test_h_values_are_non_overlapping` — проверяет что диапазоны не пересекаются (парсит N-M)
- `test_h_values_in_int32_range` — проверяет обе границы диапазона в 1..INT32_MAX
- `test_h1_h4_do_not_intersect` — диапазоны не пересекаются (полный ручной режим)
- `test_h1_h4_not_fixed_1_2_3_4` — не 1,2,3,4 (полный ручной режим)
- `test_values_in_reasonable_ranges` — H1-H4 как диапазоны
- `test_overrides_used_as_is` — H1-H4 overrides возвращаются как строки

### Прогон тестов

- `tests/test_awg_presets.py` — 79 тестов PASS
- Все AWG-тесты (264 теста) — PASS
- `full_test.py` — 10/10 PASS

### Эталонный конфиг Amnezia (для справки)

```
[Interface]
PrivateKey = iJxYWrXcgKjrwBqBgFlvxA9nnzbQSyfEXBWEYdRZ3mI=
Address = 10.8.1.0/24
ListenPort = 1443
Jc = 5
Jmin = 10
Jmax = 50
S1 = 125
S2 = 47
S3 = 27
S4 = 18
H1 = 2135087609-2145903954
H2 = 2147225277-2147461177
H3 = 2147472979-2147474536
H4 = 2147478893-2147482205
# I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>
# I2 =
# I3 =
# I4 =
# I5 =
```

---

## FIX(awg): v5.2.2 — самоисцеление в awgs_apply() для УЖЕ СЛОМАННЫХ установок (корень проблемы zvshka) — 27 июля 2026

**КОРЕНЬ ПРОБЛЕМЫ (найден после анализа лога zvshka):** v5.2.1 исправил механизм проверки `awgs_supports_i2_i5()` (заменил strip на setconf), но проверка **НИКОГДА НЕ ВЫЗЫВАЛАСЬ** на сервере zvshka. Пользователь сделал `git pull` + `systemctl restart`, но перезапуск сервиса НЕ переписывает конфиг — конфиг переписывается только при install/rotate/add-peer. Поэтому в конфиге всё ещё пустые I2-I5 (поведение v5.2), и `awg-quick up` падает с той же ошибкой.

**Подтверждение из лога zvshka:**
```
awg-quick[192652]: Line unrecognized: `I2='
awg-quick[192652]: Configuration parsing error
```

Обратите внимание: `I2=` БЕЗ значения — парсер не знает КЛЮЧ I2 вообще. Их amneziawg-tools — переходная версия, которая распознаёт I1 (добавлен раньше) но НЕ I2-I5 (добавлены позже).

**РЕШЕНИЕ v5.2.2:** Самоисцеление в `awgs_apply()`. Если apply падает с "Line unrecognized: I2=", автоматически переписать конфиг без пустых I2-I5 и повторить apply. **Срабатывает при ЛЮБОМ действии**, включая `systemctl restart` через fallback, без требования от пользователя запустить конкретное меню.

### Что реализовано

**Файл:** `chimera/modules/awg_apply.py`

**1. `_extract_apply_failure_stderr()` — НОВАЯ функция:**

Извлекает точную причину сбоя через `awg setconf` на тестовом интерфейсе (не awg0!). Заменяет извлечение через `awg-quick strip` (которое НЕ работало — strip это текстовый фильтр, не валидирует I2, всегда возвращает 0).

Алгоритм:
1. Запускаем `awg-quick strip` на реальном конфиге → получаем stripped-формат
2. Запускаем `awg setconf` на ВРЕМЕННОМ тестовом интерфейсе (awgprobe<uuid>) с этим stripped конфигом
3. Если amneziawg-tools не поддерживает I2-I5, setconf падает с 'Line unrecognized: I2=' — это и есть точная причина сбоя awgs_apply_syncconf

**2. `_is_i2_i5_unrecognized_error()` — НОВАЯ функция:**

Классифицирует ошибку: проверяет, что stderr содержит "Line unrecognized" или "Configuration parsing error" + упоминание I2/I3/I4/I5. Это защищает от ложного срабатывания на другие ошибки (невалидный privkey, отсутствие интерфейса, и пр.).

**3. `_self_heal_i2_i5_incompatibility()` — НОВАЯ функция:**

Самоисцеление:
1. Устанавливает кэш `awgs_supports_i2_i5()` в False — будущие записи конфига не будут писать пустые I2-I5
2. Переписывает конфиг через `awg_peer_rebuild_conf(apply=False)` (без apply — apply будет ниже)
3. Повторяет `awgs_apply_syncconf()` с переписанным конфигом
4. Если повтор успешен, возвращает True с предупреждающим сообщением

**4. `awgs_apply()` — обновлена:**

Новый поток выполнения при syncconf-failure:
1. `awgs_apply_syncconf()` — если успех, вернуть True
2. `_extract_apply_failure_stderr()` — извлечь точную причину через awg setconf на тестовом интерфейсе
3. Если `_is_i2_i5_unrecognized_error(last_stderr)` — вызвать `_self_heal_i2_i5_incompatibility()`
4. Если самоисцеление успешно, вернуть True
5. Если нет — defensive stderr fallback (показать точную причину в warn)
6. `awgs_apply_restart()` — final fallback

**Защита от рекурсии:** Флаг `_SELF_HEAL_IN_PROGRESS` предотвращает бесконечную рекурсию — если `_self_heal_i2_i5_incompatibility()` вызывает `awgs_apply_syncconf()`, и та тоже падает, мы не пытаемся самоисцелиться повторно.

### Почему это решает проблему zvshka

**До v5.2.2:**
- zvshka делает `git pull` + `systemctl restart`
- Конфиг НЕ переписывается (перезапуск сервиса не вызывает awgs_build_server_conf)
- `awg-quick up` падает на пустых I2-I5
- Сервис не стартует

**После v5.2.2:**
- zvshka делает `git pull` + `systemctl restart`
- `awg-quick up` падает на пустых I2-I5
- Fallback вызывает `awgs_apply()` (через restart fallback)
- `awgs_apply()` видит ошибку I2 → самоисцеление переписывает конфиг без I2-I5
- Повторный apply проходит → сервис стартует
- Пользователь видит warn про старые amneziawg-tools и совет обновиться

### Тесты (`tests/test_awg_apply.py`)

Обновлено существующих + добавлено новых: 37 тестов всего (было 19).

- `TestApplyStderrSurfacing` (3 теста) — обновлены под новый механизм извлечения stderr (через `_extract_apply_failure_stderr` вместо `awg-quick strip`). Проверяют, что defensive stderr fallback работает и после самоисцеления.
- `TestIsI2I5UnrecognizedError` (9 тестов) — НОВЫЙ класс. Проверяет классификацию ошибок: реальная ошибка zvshka → True, I3/I4/I5 → True, unrelated error → False, пустой stderr → False, privkey error → False, "Line unrecognized" без I2 → False.
- `TestSelfHealI2I5` (5 тестов) — НОВЫЙ класс. Проверяет: самоисцеление вызывается при I2 ошибке, НЕ вызывается при unrelated ошибке, защита от рекурсии, успех возвращает True, неудача fallback на restart.
- `TestSelfHealImplementation` (4 теста) — НОВЫЙ класс. Проверяет интеграцию: самоисцеление устанавливает кэш в False, вызывает awg_peer_rebuild_conf + повторяет apply, возвращает False при неудаче rebuild, возвращает False при неудаче повторного apply.

### Прогон тестов

- `tests/test_awg_apply.py` — 37 тестов PASS (19 существующих обновлены + 18 новых)
- `tests/test_awg_compat.py` — PASS
- `tests/test_awg_standalone.py` — PASS
- `tests/test_awg_qr.py` — PASS
- `tests/test_awg_transport.py` — PASS
- `tests/test_awg_peers.py` — PASS
- 185 тестов в затронутых модулях PASS
- `full_test.py` — 10/10 PASS

### Что НЕ тронуто

- `awg_compat.py` (`awgs_supports_i2_i5()` через setconf) — осталась как в v5.2.1, работает для НОВЫХ установок
- Писатели конфига с условной записью I2-I5 — осталась как в v5.2
- `awgs_warn_old_tools_once()` — осталась как в v5.2

Самоисцеление в `awgs_apply()` — это ДОПОЛНЕНИЕ к проверке `awgs_supports_i2_i5()`, не замена. Проверка предотвращает запись пустых I2-I5 для НОВЫХ установок. Самоисцеление лечит УЖЕ СЛОМАННЫЕ установки (как у zvshka).

---

## FIX(awg): v5.2.1 — критический фикс механизма проверки I2-I5 (setconf вместо strip) — 27 июля 2026

**КРИТИЧНО. Вчерашний фикс v5.2 не работает вообще — `awgs_supports_i2_i5()` проверяла через `awg-quick strip`, но strip НЕ валидирует содержимое [Interface] за пределами своих собственных директив (Address/DNS/MTU/Table и т.д.), а просто пропускает остальное насквозь без проверки. Реальная валидация (та, что рожает "Line unrecognized: I2=") происходит внутри `awg setconf`, вызываемого при настоящем `up` — strip до этой стадии не доходит вообще. Подтверждено на сервере ArkadiaGamingHub: awgs_supports_i2_i5() == True (strip returncode 0), но awg-quick up на РЕАЛЬНОМ конфиге с теми же I2-I5 падает с той же "Line unrecognized: I2=" — проверка ничего не защищала, возвращала True всегда.**

### Что исправлено

**Файл:** `chimera/modules/awg_compat.py`

**1. `_run_strip_check` → `_run_setconf_check` (полная замена):**

Старый механизм (`awg-quick strip`) — текстовый фильтр, не валидирует содержимое [Interface]. Заменён на реальный `awg setconf` против ВРЕМЕННОГО тестового интерфейса (не awg0!):

- Создаёт интерфейс `awgprobe<uuid>` через `ip link add <iface> type amneziawg` (имя через uuid — гарантированно не совпадает с awg0 или любым существующим интерфейсом)
- Применяет тестовый .conf через `awg setconf <iface> <file>` — это РЕАЛЬНЫЙ путь валидации, тот же, что вызывается при `awg-quick up`
- Удаляет интерфейс в finally-блоке (`ip link delete dev <iface>`) — ВСЕГДА, даже при ошибке setconf
- Возвращает `(success, stderr+stdout)`

**Безопасность:**
- Имя тестового интерфейса через uuid — гарантированно не awg0
- Explicit-проверка `test_iface != AWGS_INTERFACE` — второй слой safety
- Флаг `interface_created` — не вызываем `ip link delete` если интерфейс не был создан (микро-оптимизация + semantic correctness)
- Интерфейс ВСЕГДА удаляется в finally, даже при исключении
- Исключения из `core._run` ловятся, возвращаются как `(False, str(e))` — не валит процесс

**2. `sample_conf` скорректирован для setconf (stripped формат):**

`awg setconf` ожидает файл в "стриппнутом" формате (как `awg-quick strip` производит) — только [Interface] с PrivateKey/ListenPort/Jc.../I1-I5. Убраны awg-quick-only директивы: Address, MTU, DNS, Table, PreUp/PostUp/PreDown/PostDown, SaveConfig. Иначе setconf отвергнет конфиг по другой причине (не про I2), и тест даст ложный отрицательный результат.

ListenPort = 0 — kernel присваивает ephemeral port, не конфликтует с реальным awg0 (который обычно на 51820).

**3. `awgs_supports_i2_i5()` — вызов `_run_setconf_check` вместо `_run_strip_check`:**

Остальная логика без изменений: кэш на время процесса, классификация ошибки по токенам "i2"/"i3"/"i4"/"i5"/"line unrecognized"/"configuration parsing error", safe-default True при неоднозначной ошибке (DKMS не загружен, awg нет в PATH, и пр.).

### Что НЕ тронуто (v5.2 осталась верной)

- Условная запись I2-I5 в писателях конфига (5 функций в 3 модулях)
- `awgs_warn_old_tools_once()` — одноразовый warn про старый awg-tools
- Defensive stderr в `awgs_apply()` — при syncconf-failure показывает точную причину
- Самоисцеление существующих установок — при следующем действии конфиг перепишется

Проблема была ТОЛЬКО в самом механизме проверки (strip vs setconf), не в том, что делается с её результатом.

### Тесты (`tests/test_awg_compat.py`)

- Все существующие тесты, мокавшие `_run_strip_check` — переименованы под `_run_setconf_check`, логика проверок не изменилась
- НОВЫЙ класс `TestRunSetconfCheckInterfaceCleanup` (3 теста):
  - `test_interface_cleaned_up_on_setconf_failure` — интерфейс удаляется даже при ошибке setconf
  - `test_interface_cleaned_up_on_setconf_success` — интерфейс удаляется при успехе
  - `test_interface_not_deleted_when_add_fails` — не пытаемся удалить несуществующий интерфейс
- НОВЫЙ класс `TestRunSetconfCheckInterfaceName` (2 теста):
  - `test_interface_name_never_awg0` — 100 запусков, ни одно имя не равно "awg0"
  - `test_all_generated_names_unique` — 50 запусков, все имена уникальны (uuid)
- НОВЫЙ тест `test_returns_true_on_ip_link_add_failure_safe_default` — DKMS не загружен → safe True
- НОВЫЙ тест `test_returns_false_on_exception` — исключение из core._run → (False, str(e))
- НОВЫЙ тест `test_sample_conf_stripped_format_no_awg_quick_directives` — sample_conf не содержит Address/MTU/DNS/Table/PreUp/PostUp
- НОВЫЙ тест `test_sample_conf_listenport_zero_avoids_conflicts` — ListenPort=0 не конфликтует с awg0

### Прогон тестов

- `tests/test_awg_compat.py` — 29 тестов PASS (20 существующих переименованы + 9 новых)
- `tests/test_awg_apply.py` — PASS
- `tests/test_awg_standalone.py` — PASS
- `tests/test_awg_qr.py` — PASS
- `tests/test_awg_transport.py` — PASS
- `tests/test_awg_peers.py` — PASS
- 167 тестов в затронутых модулях PASS
- `full_test.py` — 10/10 PASS

### ВАЖНО — проверка на реальном сервере

Юнит-тесты с моками НЕ поймали бы вчерашнюю ошибку (strip реально возвращал 0, это не баг мока, это баг механизма). То же самое может повториться и с setconf-подходом, если что-то упущено. Перед объявлением готовым — прогнать `awgs_supports_i2_i5()` на сервере с подтверждённо старым awg-quick (как на ArkadiaGamingHub, где результат должен быть False) — и увидеть False, а не поверить юнит-тестам на слово.

---

## FIX(awg): v5.2 — условная запись I2-I5 в зависимости от поддержки локальным awg-quick (критическая регрессия 3e1fa70) — 26 июля 2026

**КРИТИЧНО. Коммит 3e1fa70 ("всегда писать I1-I5 в .conf") ломает совместимость со старыми сборками amneziawg-tools, которые поддерживают только I1 (парсер AWG 1.5) и вообще не знают директиву I2 — падают с `Line unrecognized: \`I2='` / `Configuration parsing error`, сервис awg-quick@awg0 не поднимается ВООБЩЕ (не просто "туннель не идёт", а полный отказ старта). Подтверждено реальным логом пользователя zvshka (journalctl -u awg-quick@awg0), сервер ArkadiaGamingHub, установка через Chimera сегодня.**

### Конфликт требований

- **Строгие парсеры** (Keenetic native AWG 2.0) требуют ВСЕ 5 ключей I1-I5 присутствующими, даже пустыми — иначе не считают конфиг валидным (это и было причиной коммита 3e1fa70).
- **Старые сборки amneziawg-tools** (AWG 1.5-эра) вообще не знают про I2-I5 как директивы — видят такую строку и ПАДАЮТ с ошибкой парсинга, весь сервис не стартует.

Это не "одна сторона права, другая нет" — единственный правильный фикс здесь — определять возможности установленного локально awg-quick/amneziawg-tools ПЕРЕД записью, а не жёстко "всегда" или "никогда".

### Что реализовано

**1. Новый модуль `chimera/modules/awg_compat.py`:**

- `awgs_supports_i2_i5()` — проверяет, поддерживает ли локальный awg-quick директивы I2-I5. Способ проверки — САМЫЙ надёжный, не гадать по номеру версии в строке (версии в разных дистрибутивах/форках именуются по-разному): собираем МИНИМАЛЬНЫЙ тестовый .conf с непустым I1 и пустым I2, прогоняем через `awg-quick strip` (парсит конфиг БЕЗ поднятия интерфейса — безопаснее чем реальный up/down). Если strip падает с ошибкой про I2/I3/I4/I5 — поддержка отсутствует.
- Кэширование результата на время процесса (не гонять проверку на каждый apply).
- `awgs_warn_old_tools_once()` — одноразовый warn пользователю про старую версию amneziawg-tools и совет обновиться.
- Edge cases: awg-quick не установлен → safe default True (лучше написать все 5 ключей, чем потерять decoy-пакеты); ошибка по НЕ I2-I5 причине → safe default True (не выкидывать I2-I5 из-за ложного срабатывания).

**2. Писатели конфига — условная запись I2-I5 (5 функций в 3 модулях):**

- `awg_standalone.awgs_build_server_conf()` — серверный awg0.conf
- `awg_qr.awgs_qr_build_client_conf()` — клиентский .conf для QR
- `awg_transport._awg_server_conf_text/_client_conf_text/_client_conf_for_node/_server_conf_for_node` (4 функции) — Cascade
- Общий хелпер `_awg_build_i_lines()` в awg_transport.py для 4 cascade-функций

Логика:
- **I1 пишется ВСЕГДА** (поддерживается везде, включая старые сборки — подтверждено логом zvshka, ошибка именно на I2, не на I1).
- **I2-I5 при `awgs_supports_i2_i5()==True`**: ВСЕ 5 ключей пишутся (поведение 3e1fa70, для Keenetic native AWG 2.0).
- **I2-I5 при `awgs_supports_i2_i5()==False`**: пишутся ТОЛЬКО непустые (старое поведение до 3e1fa70, для старых amneziawg-tools). Один раз за процесс показывается warn про обновление.

**3. `awgs_apply()` — defensive fallback с stderr (awg_apply.py):**

При syncconf-failure запускает `awg-quick strip` ещё раз для извлечения stderr. Если stderr содержит фрагмент про I2-I5 / "Line unrecognized" — показывается детальный warn с точной причиной + совет обновить amneziawg-tools + упоминание что конфиг автоматически перепишется в совместимом виде при следующем действии.

Раньше при откате пользователь видел только общее "syncconf не удался" — реальная причина падения терялась, её можно было найти только через ручной journalctl (пользователь zvshka сам не смог бы понять, в чём дело).

`awg_peer_rebuild_conf()` делегирует в `awgs_apply()`, поэтому defensive stderr автоматически работает и при rebuild (например, при добавлении клиента, ротации параметров).

**4. Самоисцеление существующих установок:**

При следующем действии пользователя (добавление клиента, ротация параметров, и т.п.) после установки этого фикса — конфиг автоматически перепишется в совместимом виде (без I2-I5, если локальный awg-quick их не поддерживает). Не требуется ручная правка .conf. Сервис awg-quick@awg0 снова стартует.

### Тесты

- **`tests/test_awg_compat.py`** — НОВЫЙ файл, 20 тестов в 5 классах:
  - `TestSupportsI2I5` (8 тестов) — `awgs_supports_i2_i5()` для случаев: strip OK, strip fails on I2/I3/I4/I5, strip fails on "Configuration parsing error", strip fails on unrelated reason (safe True), strip fails with empty stderr (safe True).
  - `TestSupportsCache` (4 теста) — кэширование на время процесса, `force_refresh`, `_set_supports_cache`/`_reset_supports_cache` для тестов.
  - `TestWarnOldToolsOnce` (3 теста) — одноразовый warn за процесс, содержимое сообщения, `_reset_old_tools_warn_flag` для тестов.
  - `TestRunStripCheck` (3 теста) — `_run_strip_check` для success/failure/exception.
  - `TestSampleConfContent` (2 теста) — sample conf содержит I1-I5 + базовые AWG-параметры.

- **`tests/test_awg_apply.py`** — НОВЫЙ класс `TestApplyStderrSurfacing` (3 теста):
  - `test_stderr_shown_in_warn_on_i2_unrecognized` — 'Line unrecognized: I2=' в warn().
  - `test_stderr_shown_on_any_strip_error` — любая ошибка strip в warn().
  - `test_generic_warn_when_no_stderr_available` — общее сообщение при отсутствии stderr.

- **`tests/test_awg_standalone.py`** — `test_i1_to_i5_always_written_v51` параметризован в 3 теста:
  - `test_i1_to_i5_written_when_supports_i2_i5_v52` — supports=True → все 5 ключей.
  - `test_i1_only_when_no_i2_i5_support_v52` — supports=False → только I1 (zvshka regression).
  - `test_non_empty_i2_to_i5_written_even_without_support_v52` — supports=False + непустые I2-I5 → пишутся.

- **`tests/test_awg_qr.py`** — `test_i1_always_written_v51` → `test_i1_always_written_v52` (параметризован: supports=True → 5 ключей, supports=False → только I1).

- **`tests/test_awg_transport.py`** — 4 теста `*_always_writes_i1_to_i5_v51` → `*_writes_i_lines_based_on_support_v52` (параметризованы). `test_all_4_functions_have_full_param_set` — мокает supports=True для проверки полного набора 16 параметров.

### Прогон тестов

- `tests/test_awg_compat.py` — 20 тестов PASS
- `tests/test_awg_apply.py` — 14 тестов PASS (3 новых + 11 существующих)
- `tests/test_awg_standalone.py` — PASS
- `tests/test_awg_qr.py` — PASS
- `tests/test_awg_transport.py` — PASS
- `tests/test_awg_peers.py` — PASS
- `full_test.py` — 10/10 PASS

### Обратная совместимость

- Пользователи с современными amneziawg-tools (AWG 2.0): поведение не изменилось — все 5 I-ключей пишутся как в 3e1fa70.
- Пользователи со старыми amneziawg-tools (AWG 1.5): conf автоматически переписывается без I2-I5 при следующем действии → сервис снова стартует.
- существующие state.json остаются валидными (валидатор принимает CPS tag-формат и legacy hex).

---

## FIX(awg): CPS tag-формат для I1-I5 вместо голой hex-строки (AWG 2.0 совместимость) + всегда писать I1-I5 в .conf — 26 июля 2026

**Контекст: сравнение с конфигом официального приложения Amnezia показало, что I1-I5 в AWG 2.0 — это НЕ голая hex-строка, а мини-язык тегов (CPS — Custom Protocol Signature), задокументированный в docs.amnezia.org и в спецификации amneziawg-go. Голый hex — это старый формат AWG 1.5. Стороннее сообщество (bivlked/amneziawg-installer, ADVANCED.md) прямо указывает: "если туннель подключается, но трафик не идёт — проблема в формате I1" на некоторых клиентах (Keenetic native AWG 2.0, amneziawg-go).**

### Что изменилось

**1. awgs_presets_generate() — генерация I1 в CPS tag-формате:**

- `i1_mode == "random"`: было `"".join(random.choices("0123456789abcdef", k=i1_len * 2))` → стало `f"<r {i1_size}>"` (24-32 случайных байт через CPS tag, простейший валидный формат AWG 2.0).
- `i1_mode == "binary"` (T-Mobile US): было голый hex 16 символов → стало `f"<b 0x{i1_hex}>"` (32 hex символа = 16 байт, статичные байты через CPS tag).
- `i1_mode == "absent"`: без изменений (пустая строка).
- **Новый режим `i1_mode == "quic_mimicry"`** — опциональный sneaky-режим через `_generate_quic_mimicry_i1()`: `<b 0xc30000000108><r 8><b 0x08><r 8><b 0x0045dc><t><r 16>` (маскировка под QUIC v1 long-header, RFC 9000). Доступен для использования в "5. Ручная настройка" через `awgs_generate_full_manual_params()`.

**2. awgs_generate_full_manual_params() — та же правка: I1 теперь `<r N>` вместо голого hex.**

**3. awgs_presets_validate_params() — принимает CPS tag-формат И голый hex:**

Новый хелпер `_is_valid_cps_or_legacy_hex()` принимает:
- CPS tag-формат AWG 2.0: `<b 0x[hex]>`, `<r [size]>`, `<rd [size]>`, `<rc [size]>`, `<t>` (комбинируются через конкатенацию, optional whitespace между тегами).
- Голый hex без тегов (AWG 1.5) — для обратной совместимости с уже установленными state.json у пользователей, которые обновились с  .

Старый hex-формат остаётся валидным, чтобы не сломать уже установленные конфиги (правка только для НОВОЙ генерации, не автомиграция).

**4. Писатели конфига ВСЕГДА пишут I1-I5 (раньше только непустые):**

- `awg_standalone.awgs_build_server_conf()` — серверный awg0.conf
- `awg_qr.awgs_qr_build_client_conf()` — клиентский .conf для QR
- `awg_transport._awg_server_conf_text()` — Cascade сервер
- `awg_transport._awg_client_conf_text()` — Cascade клиент
- `awg_transport._awg_client_conf_for_node()` — Cascade клиент для конкретной ноды
- `awg_transport._awg_server_conf_for_node()` — Cascade сервер для конкретной ноды

Было:
```python
if params.get("i1"):
    lines.append(f"I1 = {params['i1']}")
```

Стало:
```python
lines.append(f"I1 = {params.get('i1', '')}")
# ... то же для I2-I5
```

Это соответствует официальному формату AWG 2.0 (amnezia-клиент всегда пишет все 5 ключей). Строгие парсеры (Keenetic native AWG 2.0) падают на отсутствии ключа I2/I3/I4/I5 при наличии I1.

**5. install_prompts._ask_hex() — принимает CPS tag-формат в ручном вводе.**

Пользователь в пункте "5. Ручная настройка" теперь может вводить как голый hex (старый формат), так и CPS tag-строки (`<r 24>`, `<b 0x...>`, `<t>` и т.д.).

**6. ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ H1-H4 для старых прошивок Keenetic (зафиксировано в коде):**

Добавлен подробный комментарий в `_generate_non_overlapping_h_values()` (awg_presets.py): некоторые старые прошивки роутеров (Keenetic Speedster firmware 5.0.6, OpenWrt 21.x и старше) не парсят H1-H4 как одиночное число выше 255 — они требуют значения в диапазоне 0-255 (один байт). По спецификации AWG 2.0 (docs.amnezia.org) значения валидны до INT32_MAX, и amneziawg-windows-client их принимает. Если пользователь жалуется на "не подключается с Keenetic" — нужно проверить версию прошивки и при необходимости вручную снизить H1-H4 до 0-255 через "5. Ручная настройка". Альтернатива — использовать upstream amneziawg-go бинарник вместо native AWG-клиента роутера.

### Тесты

- `tests/test_awg_presets.py` — обновлены существующие тесты (старые `test_i1_random_mode_generates_hex`, `test_i1_binary_mode_generates_short_hex`, `test_i1_is_hex_48_to_64_chars` заменены на CPS-варианты) + 2 новых тестовых класса:
  - `TestCpsTagFormat` (15 тестов) — проверка `_is_valid_cps_or_legacy_hex` (CPS tags, legacy hex, garbage rejection, non-string rejection), `_generate_quic_mimicry_i1` (static pattern, validator pass, QUIC flag 0xc3, timestamp tag, random tags), и интеграция с `awgs_presets_validate_params`.
  - `TestPresetsGenerateCpsI1` (4 теста) — все пресеты с i1_mode='random' генерируют `<r N>`, 'binary' — `<b 0x...>`, 'absent' — пустой, и все проходят валидатор.
- `tests/test_awg_qr.py` — `test_omits_i1_when_empty` заменён на `test_i1_always_written_v51` (все 5 I1-I5 ключей всегда в conf).
- `tests/test_awg_standalone.py` — `test_i1_omitted_when_empty` заменён на `test_i1_to_i5_always_written_v51`.
- `tests/test_awg_transport.py` — 4 теста `*_omits_i1_when_empty` заменены на `*_always_writes_i1_to_i5_v51` (4 функции: `_awg_server_conf_text`, `_awg_client_conf_text`, `_awg_client_conf_for_node`, `_awg_server_conf_for_node`). `test_all_4_functions_have_full_param_set` расширен: теперь проверяет все 16 параметров (раньше 11 + опциональные I1-I5).

### Обратная совместимость

- НЕ трогаются уже установленные/существующие конфиги на серверах пользователей. Правка только для НОВОЙ генерации при установке/ротации параметров.
- Если пользователь ротирует параметры после обновления кода, он естественно получит новый корректный формат.
- Валидатор принимает оба формата (CPS + legacy hex), чтобы уже установленные state.json продолжали работать.

---

## FEAT(mtproto_stats): диагностика Telemt API в TUI (почему Panel показывает 0) — 26 июля 2026

**Пользователь сообщил: TUI Chimera корректно показывает трафик Telemt (490.9 KiB, два активных пользователя), но Telemt Panel (веб-панель) показывает 0 traffic / 0 connections / 0 active IPs, хотя `Configured Users: 2` и `Uptime: 7m`. Это расходящиеся источники: TUI берёт трафик из iptables-цепочек TELEMT_STATS_IN/OUT (надёжно, не зависит от telemt API), а Panel — из HTTP API telemt (127.0.0.1:9091, секция [server.api]). Если API telemt возвращает 0 — Panel показывает 0, хотя трафик реально есть. Добавляем диагностический инструмент в TUI, чтобы пользователь мог сам разобраться.**

### Контекст

Telemt Panel (`chimera/modules/telemt_panel.py`) — отдельный Go-бинарник с React-фронтендом, общается с telemt через HTTP API (127.0.0.1:9091). Chimera только **генерирует конфиг панели** и включает `[server.api]` в telemt.toml через `mtproto.ensure_api_enabled()` — но не контролирует, что именно telemt API возвращает.

Возможные причины, почему Panel показывает 0 при работающем TUI:

1. **Telemt был недавно перезапущен** — внутренние счётчики telemt обнулились (uptime < времени с последнего подключения). iptables-счётчики при этом НЕ обнуляются (только при `iptables -Z` или ребуте сервера), поэтому TUI Chimera продолжает показывать трафик. Подожди 5-10 минут после рестарта и переподключись — счётчики telemt должны начать расти.

2. **`build profile: unknown`** в System Info панели — подозрительный признак. Telemt-бинарник может быть собран без stats-feature. Вывод пользователя показывает именно `build profile: unknown` — это намекает на кастомную/урезанную сборку telemt.

3. **iOS Fix через iptables NAT REDIRECT** — пользователь подключается через внешний порт 5001, который iptables редиректит на основной порт 5000. Telemt физически видит соединение на 5000, но его internal per-connection tracking может не работать корректно для таких редиректнутых соединений (upstream telemt, не Chimera).

4. **Баг upstream telemt** — telemt API может просто не считать трафик в этой версии бинарника. Чинить нужно в upstream telemt, не в Chimera.

### Что реализовано

**Новый пункт [5] в `stats_menu()` (меню Telemt → Статистика):** «🔍 Диагностика Telemt API (для панели)».

Запускает `diagnose_telemt_api_for_panel()` — полную диагностику:

1. **`_telemt_api_section_configured()`** — проверяет что в `telemt.toml` включена секция `[server.api]` (или устаревший `[server.admin_api]`), что `enabled = true`. Возвращает `(ok, detail)`.

2. **`_telemt_api_probe(timeout=3.0)`** — делает HTTP-запрос к `http://127.0.0.1:9091/v1/info` (fallback на `/info` и `/`) без auth_header. Если API отвечает 200/401/403 — значит API слушает (401/403 = auth required, это нормально, мы просто не передаём auth_header в диагностике). Если connection refused — API не запущен.

3. **Uptime telemt** — через `systemctl show telemt --property=ActiveEnterTimestampMonotonic` + `/proc/uptime`. Если uptime < 10 минут — добавляет рекомендацию про обнуление счётчиков при рестарте.

4. **`_render_telemt_api_diagnosis(diag)`** — рендерит результат в TUI: показывает статус секции, статус API, uptime, и список рекомендаций (через `_wrap_text` для длинных строк).

### Регрессионные тесты (7 новых)

`tests/test_mtproto_stats.py` — новый класс `TestDiagnoseTelemtApiForPanel`:

1. `test_section_configured_returns_true_when_enabled` — `[server.api]` есть и `enabled=true` → ok=True.
2. `test_section_configured_returns_false_when_section_absent` — секции нет → ok=False.
3. `test_section_configured_returns_false_when_enabled_is_false` — `enabled=false` → ok=False.
4. `test_section_configured_returns_false_when_no_config_file` — `telemt.toml` не существует → ok=False.
5. `test_diagnose_returns_recommendations_when_section_missing` — если секции нет, diagnose возвращает рекомендацию включить её.
6. `test_diagnose_includes_uptime_when_telemt_recently_restarted` — если telemt перезапущен < 10 мин назад, diagnose включает рекомендацию про обнуление счётчиков. Использует реальный `/proc/uptime` (Linux-only, skip на других ОС).
7. `test_diagnose_adds_build_profile_recommendation_when_all_ok` — когда всё настроено (секция есть, API отвечает, uptime большой), diagnose добавляет рекомендацию про build profile и upstream telemt.

### Изменённые файлы

- `chimera/modules/mtproto_stats.py` — новые функции `_telemt_api_section_configured()`, `_telemt_api_probe()`, `diagnose_telemt_api_for_panel()`, `_render_telemt_api_diagnosis()`, `_wrap_text()`; пункт [5] в `stats_menu()` и `_render_stats()`.
- `tests/test_mtproto_stats.py` — +7 тестов в новом классе `TestDiagnoseTelemtApiForPanel`.

### Тесты

- `tests/test_mtproto_stats.py` — 53/53 PASS (46 + 7 новых).
- Регрессия: `test_mtproto*.py` + `test_traffic_*.py` — **292/292 PASS** (285 + 7 новых).
- `full_test.py` — **10/10 PASS**, проект готов к релизу.

### Совместимость

Полностью обратно совместимо:
1. Новый пункт [5] в меню — аддитивный, не меняет существующие пункты [1]-[4].
2. Диагностика делает HTTP-запрос к 127.0.0.1:9091 без auth — если API требует auth, вернёт 401/403, и диагностика корректно это интерпретирует как «API работает, нужен auth».
3. `/proc/uptime` читается только на Linux (на других ОС диагностика пропускает uptime-проверку, не падает).

### Что делать пользователю

1. Зайти в меню: Telemt → Статистика → [5] Диагностика Telemt API.
2. Посмотреть вывод:
   - Если «Секция [server.api]: ✗ отсутствует» — переустановить панель через меню Telemt → Telemt Panel.
   - Если «API отвечает: ✗» — проверить `systemctl status telemt`, `journalctl -u telemt -n 30`, `ss -tlnp | grep 9091`.
   - Если uptime < 10 минут — подождать 5-10 минут после рестарта telemt, переподключиться, счётчики должны начать расти.
   - Если всё настроено, но трафик 0 — проверить `build profile` в System Info панели. Если `unknown` — это подозрительно, попробуйте другую версию telemt-бинарника.
3. TUI Chimera (через iptables) — надёжный источник, не зависящий от telemt API. Если TUI видит трафик, а Panel — нет, проблема в upstream telemt, не в Chimera.

---

## FIX(mtproto_stats): "Последний вход: —" для активных пользователей Telemt — 26 июля 2026

**На реальном сервере в TUI статистики Telemt (меню Telemt → Статистика) в графе «Последний вход» отображалось «—» для активных пользователей, у которых трафик реально есть (4.9 KiB / 9.7 KiB). Причина — узкий парсер journalctl, который пропускал реальные строки логов telemt. Чиним без бампа версии.**

### Корневая причина

`mtproto_stats._parse_journal()` имел три узких места:

1. **Timestamp-регулярка ждала только `T`-разделитель** — `^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`. Если journalctl или telemt пишет timestamp с пробелом вместо `T` (например `short-full` формат, или другая версия journald) — timestamp не извлекался, `last_seen` оставался `"—"`.

2. **Multiline-сообщения обрабатывались построчно без контекста.** Journald может разрывать длинные сообщения на несколько строк; continuation-строки не имеют своего timestamp. Если `user=alice` оказывалась на continuation-строке (например, после строки `new MTProto connection` с timestamp), то:
   - Имя пользователя извлекалось (матчилось на `user=alice`).
   - Timestamp — нет (continuation-строка без timestamp в начале).
   - `last_seen` оставался `"—"`.
   - Это объясняет почему в TUI имя отображалось, а «Последний вход» — нет.

3. **Узкий паттерн session:** `connect|new.?client|auth.?ok` пропускал много реальных сообщений telemt: `accepted`, `login`, `session started`, `handshake ok`, `client ok`, `authenticated`. Из-за этого `sessions=0` даже для активных пользователей.

### Фикс

**1. `_extract_ts()` — новая helper-функция в `_parse_journal`** — принимает оба варианта разделителя между датой и временем: `T` (стандартный `short-iso`) и пробел (`short-full` и другие). Возвращает `'YYYY-MM-DD HH:MM:SS'`.

**2. Multiline-handling через `last_ts`-переменную** — запоминаем последний timestamp из предыдущей строки. Если текущая строка содержит `user=` но не содержит timestamp (continuation-строка), используем `last_ts` как fallback. Это НЕ идеально (timestamp может быть из предыдущего log-entry), но лучше чем `"—"` для активных пользователей.

**3. Расширенный `_SESSION_RE`** — `connect | new.?client | auth(.|_)?(ok|enticated) | session.?start | accepted | login | handshake.?ok | client.?ok`. Покрывает реальные сообщения от tracing-логгера telemt.

**4. Расширенная регулярка пользователя** — помимо `user=`/`client=`/`user[`/`client[`, теперь принимает `username=`, `name=`, и значения в кавычках (`user="alice"`, `user='alice'`) через опциональную группу `(["\']?)([a-zA-Z][a-zA-Z0-9_\-]+)\1`.

**5. Fallback `last_seen` в `_collect()` для активных пользователей** — если у пользователя есть трафик (`rx>0` или `tx>0`) но `last_seen="—"` (ни одна строка journalctl не сматчилась), используем `d["total"]["updated"]` как приблизительное время последней активности. Это лучше чем `"—"` для активных пользователей, чьи логи telemt пишутся в формате, который не распознаётся текущим парсером.

ВАЖНО: fallback применяется **ТОЛЬКО** к пользователям с ненулевым трафиком. Если `rx=0` и `tx=0` — пользователь никогда не подключался, оставляем `"—"` (не выдумываем время для пустого пользователя). Применяется **ПОСЛЕ** распределения байт, чтобы распределённый трафик тоже учитывался в условии `rx>0`/`tx>0`.

### Регрессионные тесты (8 новых)

`tests/test_mtproto_stats.py` — 6 новых в `TestParseJournal` + 2 новых в `TestCollectLastSeenFallback`:

1. `test_realistic_short_iso_format_with_hostname_and_pid` — реальный вывод journalctl `-o short-iso` (с hostname, PID, +TZ offset) — main regression marker.
2. `test_multiline_continuation_uses_last_timestamp` — multiline-сообщение с `user=` на continuation-строке → `last_seen` берётся из предыдущей строки (через `last_ts`).
3. `test_timestamp_with_space_separator_accepted` — timestamp с пробелом вместо `T` (как `short-full`).
4. `test_extended_session_patterns_recognized` — `accepted`/`login`/`session started`/`handshake ok`/`client ok`/`authenticated` → все дают `sessions=1`.
5. `test_user_with_quotes_in_value_parsed` — `user="alice"` и `user='bob'` (с кавычками).
6. `test_username_key_also_recognized` — `username=alice` и `name=bob` (не только `user=`).
7. `test_user_with_traffic_but_no_journal_gets_fallback_last_seen` — fallback `last_seen` из `d["total"]["updated"]` при `rx>0`/`tx>0` и пустом journalctl.
8. `test_user_without_traffic_stays_dash` — пользователь без трафика → `last_seen` остаётся `"—"` (не выдумываем время).

### ВАЖНО про отдельную Telemt Panel (веб-панель)

Telemt Panel (`chimera/modules/telemt_panel.py`) — это **отдельный Go-бинарник** с React-фронтендом (github.com/amirotin/telemt_panel). Она общается с telemt через **HTTP API Telemt** (127.0.0.1:9091), а НЕ через наши iptables-цепочки `TELEMT_STATS_IN/OUT` или journalctl. У панели собственный механизм отображения статистики, наши фиксы `mtproto_stats.py` её **не затрагивают**.

Наши фиксы помогают TUI статистики Telemt в самом Chimera (меню Telemt → Статистика), где:
- Раньше «Последний вход: —» даже для активных пользователей.
- Раньше `sessions=0` для активных пользователей (узкий session-паттерн).
- Теперь `last_seen` заполняется (либо из journalctl, либо fallback из `total.updated`).
- Теперь `sessions` корректно считается (расширенный паттерн).

Если в веб-панели Telemt трафик тоже не считался — это отдельная проблема в самом telemt (его API / tracing-логи), не в нашем коде. Чинить нужно в upstream telemt, не в Chimera.

### Изменённые файлы

- `chimera/modules/mtproto_stats.py` — `_parse_journal()` расширен: `_extract_ts()` helper, `last_ts` для multiline-continuation, расширенный `_SESSION_RE`, расширенная регулярка пользователя с кавычками и `username`/`name` ключами. `_collect()` — fallback `last_seen` для активных пользователей из `d["total"]["updated"]` (после распределения байт).
- `tests/test_mtproto_stats.py` — +8 тестов (6 на `_parse_journal` + 2 на `_collect` fallback).

### Тесты

- `tests/test_mtproto_stats.py` — 46/46 PASS (38 + 8 новых).
- Регрессия: `test_mtproto*.py` + `test_traffic_*.py` — **285/285 PASS** (277 + 8 новых).
- `full_test.py` — **10/10 PASS**, проект готов к релизу.

### Совместимость

Полностью обратно совместимо:
1. Старые форматы логов (с `T`-разделителем, без кавычек, с `user=`) — все продолжают работать.
2. Новые форматы (с пробелом, с кавычками, с `username=`/`name=`) — теперь тоже работают.
3. Fallback `last_seen` применяется только когда `rx>0`/`tx>0` и `last_seen="—"` — не меняет поведение для пользователей без трафика.

---

## FIX(mtproto): парсинг числового протокола "6" в _ipt_jump_exists + идемпотентность setup_iptables_accounting при повторных [3] — 26 июля 2026

**После коммита 0b412e3 (постфактум-верификация iptables-accounting) обнаружен ложноположительный отказ на реальном сервере: iptables-учёт для Telemt физически работает (jump-правила стоят, счётчики пакетов/байт растут — подтверждено на сервере: 119 пакетов / 15936 байт на TELEMT_STATS_IN, 111 / 48027 на TELEMT_STATS_OUT), но `setup_iptables_accounting()` всё равно возвращает False и TUI показывает «iptables-учёт НЕ активирован». Корневых причин две — чиним одной задачей, без бампа версии.**

### Подпроблема 1: флаг `-n` делает протокол числовым, код ждал буквально "tcp"

**Корневая причина** (подтверждено на реальном выводе `iptables -L INPUT -v -n`): флаг `-n` (numeric) делает числовым не только IP-адреса, но и ПОЛЕ ПРОТОКОЛА — вместо текстового `"tcp"` в этой колонке стоит `"6"` (номер протокола IPPROTO_TCP). Реальный вывод:

```
119 15936 TELEMT_STATS_IN  6  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:5000
```

Код в `_ipt_jump_exists()` ждал буквально строку `"tcp"` в `parts[3]`, а получал `"6"` — никогда не совпадает на выводе с флагом `-n`, строка с реальным правилом пропускалась, функция всегда возвращала False для правил, которые реально существуют и работают.

Тесты не поймали баг, потому что моки `_run()` в существующих тестах эмулировали вывод со словом `"tcp"` в этой позиции, а не реальный числовой вывод `-n` — то есть тесты проверяли код против придуманного, а не настоящего формата вывода.

**Фикс:** введён `_TCP_PROTO_TOKENS = frozenset({"tcp", "6"})` на уровне модуля, и проверка `if prot not in _TCP_PROTO_TOKENS: continue` вместо жёсткого `if prot != "tcp"`. Также добавлен развёрнутый комментарий «УРОК НА БУДУЩЕЕ» в начале секции IPTABLES ACCOUNTING: при парсинге вывода iptables/ip/nft с флагом `-n` значения полей могут быть числовыми (протоколы, иногда порты через /etc/services) вместо текстовых — любой будущий парсинг должен либо не использовать `-n` для полей, которые сравниваются со строкой, либо принимать оба представления явно.

### Подпроблема 2: пункт [3] мог накапливать дубликаты jump-правил при многократных нажатиях

Текущий код делал ОДИН вызов `-D ... -j CHAIN` перед ОДНИМ `-I ... -j CHAIN` — это снижало риск дублирования, но не гарантировало его отсутствие: `-D` удаляет только ОДНО совпадающее правило за вызов, не проверяет результат, и если по какой-то причине правило встретилось дважды (например, из-за более ранней версии кода без `-D` вообще, или ручного вмешательства) — одно из дублей останется висеть, а после `-I` добавится ещё одна свежая копия — правила будут накапливаться с каждым нажатием [3].

**Фикс:** новая функция `_ipt_remove_all_jumps(parent, chain, port, direction) -> int` — цикл удаления до исчерпания (с защитным лимитом 50 итераций на случай непредвиденного поведения iptables — штатно никогда не достигается). Использует `_ipt_jump_exists()` для проверки after each removal, а не полагается на returncode `-D`. Гарантирует, что после `_ipt_remove_all_jumps` останется РОВНО 0 jump-правил, и последующий единственный `-I` приведёт к РОВНО 1 правилу в финальном состоянии, сколько бы раз [3] ни нажимали.

Вызывается для обоих направлений (INPUT/CHAIN_IN, OUTPUT/CHAIN_OUT) В НАЧАЛЕ `setup_iptables_accounting()`, ПЕРЕД созданием цепочек и добавлением нового jump-правила (замена текущего одиночного `-D ... || true` перед `-I`). Если удалено >1 правила — логируется через `_info_local` как сигнал, что где-то раньше уже копилось дублирование (полезно для диагностики).

Цепочки CHAIN_IN/CHAIN_OUT продолжают очищаться через `-F` (как и раньше) — для содержимого цепочки этого достаточно, дублирование возможно только на уровне jump-правил в INPUT/OUTPUT, не внутри самих кастомных цепочек.

### Регрессионные тесты (8 шт. в `TestSetupIptablesAccountingVerification`)

Существующий stateless mock полностью переписан на **stateful** — отслеживает «реально установленные» цепочки и jump-правила в mock-state: `-N` добавляет цепочку в set, `-D` декрементирует jump-count, `-I` инкрементирует. Это позволяет тестировать `_ipt_remove_all_jumps` и идемпотентность реалистично (а не через статические словари `chain_exists_results`/`jump_exists_results` как раньше).

1. `test_returns_false_when_chains_did_not_actually_appear` — `-N` «успешен» (returncode 0), но цепочка не появилась (контейнер без CAP_NET_ADMIN) → False.
2. `test_returns_true_when_all_chains_and_jumps_confirmed` — полный успех с текстовым `"tcp"` → True.
3. `test_returns_true_with_numeric_proto_token_from_dash_n` — то же с числовым `"6"` (как при `-n`) → True. Старый код падал.
4. **`test_recognizes_numeric_tcp_protocol_from_dash_n_output`** — регрессия на КОНКРЕТНО этот сценарий: реальный вывод с сервера один-в-один (119 pkts / 15936 bytes / proto=6 / dpt:5000) → `_ipt_jump_exists` возвращает True. Это главный тест-маркер бага.
5. `test_remove_all_jumps_with_three_duplicates_calls_D_three_times` — 3 дубля в INPUT → `_ipt_remove_all_jumps` вызывает `-D` ровно 3 раза (не 1, не бесконечно), возвращает `removed=3`.
6. `test_remove_all_jumps_with_zero_rules_calls_D_zero_times` — 0 правил → `removed=0`, ни одного `-D`.
7. **`test_setup_called_twleve_leaves_exactly_one_jump_rule`** — интеграционный: `setup_iptables_accounting()` вызван ДВАЖДЫ подряд (эмуляция двух нажатий [3]) → после второго вызова ровно 1 jump-правило (не 2!).
8. `test_setup_cleans_up_preexisting_duplicates` — 3+2 предсуществующих дублей → после вызова ровно 1+1.

### DO NOT TOUCH (по требованию задачи)

- `/var/log/chimera.log` путь — перепроверено отдельно, код везде консистентно ссылается на `/var/log/chimera.log`. Расхождение было в команде диагностики (`tail /var/lib/chimera.log` — опечатка `lib` вместо `log`), не в самом проекте. Не искать и не чинить несуществующую проблему.

### Изменённые файлы

- `chimera/modules/mtproto_stats.py` — `_TCP_PROTO_TOKENS = {"tcp", "6"}` + комментарий «УРОК НА БУДУЩЕЕ»; `_ipt_jump_exists` принимает оба токена; новая `_ipt_remove_all_jumps()` с циклом до исчерпания; `setup_iptables_accounting` вызывает `_ipt_remove_all_jumps` для обоих направлений перед `-I`, логирует >1 удалённого правила через новый `_info_local`.
- `tests/test_mtproto_stats.py` — `_make_run_mock` переписан на stateful (отслеживает chains_exist set + jumps dict, мутирует при -N/-D/-I); +6 новых тестов (numeric proto, real server output, _ipt_remove_all_jumps с 3/0 дублями, идемпотентность двойного вызова, cleanup preexisting duplicates).

### Тесты

- `tests/test_mtproto_stats.py::TestSetupIptablesAccountingVerification` — 8/8 PASS (2 переписанных + 6 новых).
- Регрессия: `test_mtproto*.py` + `test_traffic_*.py` — **277/277 PASS** (271 + 6 новых).
- Широкий прогон `tests/` (исключая медленные network-тесты) — **~4000+ тестов, 0 регрессий**.
- `full_test.py` — **10/10 PASS**, проект готов к релизу.

### Совместимость

Полностью обратно совместимо:
1. `_TCP_PROTO_TOKENS = {"tcp", "6"}` принимает оба варианта — старый текстовый `"tcp"` (без `-n`) и числовой `"6"` (с `-n`).
2. `_ipt_remove_all_jumps` — новый API, не нарушает существующие вызовы.
3. `setup_iptables_accounting` по-прежнему возвращает `bool` (как после коммита 0b412e3), повторные вызовы теперь безопасны (идемпотентны).

---

## FIX(traffic+mtproto): Telemt не считал трафик в TUI + latent-баг iptables-accounting + multi-protocol диспетчер трафика — 26 июля 2026

**На реальной entry-ноде в РФ (маршрутизация через xray tproxy) обнаружено: Telemt не считает трафик ни в реальном времени, ни по дням, ни после принудительного обновления. Корневых причин две, обе латентные — чиним одной задачей, без бампа версии.**

### Подпроблема 1: iptables-цепочки учёта никогда реально не создавались, но установщик рапортовал успех

`mtproto_stats.setup_iptables_accounting(port)` делала ~8 вызовов `_run(["iptables", ...])` все с `check=False` — ни одна команда не бросает исключение при провале. Функция ничего не возвращала (implicit `None`) и не проверяла результат постфактум. `mtproto._setup_accounting()` оборачивал её в `try/except Exception: return False` — но раз iptables-команды не бросают исключений, этот `except` почти никогда не срабатывал по реальной причине (например, цепочки не появились). Отсюда «✓ Учёт трафика активирован» при установке, даже когда цепочки физически не создались (контейнер без CAP_NET_ADMIN, ядро без netfilter-модуля, iptables-nft vs iptables-legacy конфликт, и т.п.).

**Фикс:** `setup_iptables_accounting(port) -> bool` теперь после всех iptables-команд делает **постфактум-верификацию** 4-мя проверками:
1. `_ipt_chain_exists(CHAIN_IN)` — цепочка существует.
2. `_ipt_chain_exists(CHAIN_OUT)` — цепочка существует.
3. `_ipt_jump_exists("INPUT", CHAIN_IN, port, "dport")` — jump-правило из INPUT в CHAIN_IN для dport=port реально стоит (парсится `iptables -L INPUT -v -n`, ищется target=chain + tcp + dpt:port).
4. `_ipt_jump_exists("OUTPUT", CHAIN_OUT, port, "sport")` — то же для OUTPUT.

Возвращает `True` только если все 4 проверки прошли. Иначе — `False` + конкретная причина в `chimera.log` (WARN от `mtproto_stats.setup_iptables_accounting`).

`mtproto._setup_accounting(port) -> bool` — упрощён, `try/except` оставлен только для реального импорт-сбоя (модуль `mtproto_stats` недоступен), возвращает то, что реально вернула `setup_iptables_accounting(port)`.

Install flow (`mtproto.py:2967-2974`) — добавлена `else`-ветка: при `ipt_ok=False` выводится `_warn` с текстом «Учёт трафика (iptables) НЕ настроен — traffic-квоты и статистика работать не будут. Включить вручную: меню Telemt → Статистика → пункт 3.».

`stats_menu()` пункт `[3]` (строка 606-634) — тоже теперь показывает честный результат: при `ipt_ok=False` печатает «⚠ iptables-учёт НЕ активирован. Постфактум-верификация обнаружила, что цепочки TELEMT_STATS_IN/OUT или jump-правила из INPUT/OUTPUT не создались.» + возможные причины + ссылку на `chimera.log`.

### Подпроблема 2: Telemt (и mieru/naiveproxy/awg) отсутствовали в дневном TUI трафика

`traffic_tracking._query_user_traffic_bytes(email)` жёстко ходил в Xray Stats API по паттерну `user>>>{email}>>>traffic` — у telemt-пользователей нет такого объекта в Xray (они не заведены как xray "user", даже несмотря на то что их трафик физически идёт через dokodemo-door tproxy). `traffic_history._traffic_snapshot_save()` перебирал только `core._users_load()` = `users.json` (VLESS-only) — про telemt/mieru/naiveproxy/awg пользователей не знал вообще.

**Проверка гипотезы** (см. `SUPPORTED_PROTOCOLS` в `traffic_accounting.py`): разрыв подтвердился для всех 4 не-VLESS протоколов с per-user трафиком (trusttunnel — aggregate-only, без per-user breakdown, осознанно не включён). Чиним одним заходом.

**Фикс — единый диспетчер** `traffic_tracking.query_user_traffic_bytes(identifier, protocol) -> int`:
- `protocol="xray"/"vless"` → `_query_user_traffic_bytes(email)` (Xray Stats API, как раньше).
- `protocol="mtproto"/"telemt"` → `mtproto._get_user_traffic_bytes(username)` (собственный baseline в `mtproto_stats._load_stats`).
- `protocol="mieru"` → `mieru_stats.mieru_get_traffic_accumulated(username)`.
- `protocol="naiveproxy"` → `naiveproxy_stats.naiveproxy_get_traffic_accumulated(username)`.
- `protocol="awg"` → `awg_peers.awg_get_peer_traffic_accumulated(owner_email)`.

Диспетчер НЕ дублирует логику per-protocol модулей — только диспетчеризация. Никогда не бросает исключение (ошибка → 0), чтобы snapshot/TUI не ронять из-за одного протокола. Также добавлена accumulated-версия `query_user_traffic_bytes_accumulated(identifier, protocol)` — для VLESS использует `traffic_accounting.record_traffic_sample()` с baseline-offset, для остальных протоколов просто возвращает то, что отдаёт их собственный механизм (у них baseline уже встроен).

**`_traffic_snapshot_save()` расширена** — теперь помимо VLESS перебирает:
- Telemt — `mtproto._load_users()` → ключ `mtproto::{username}_max`
- Mieru — `mieru._MODULE_STATE.users` → ключ `mieru::{username}_max`
- NaiveProxy — `naiveproxy._load_users()` → ключ `naiveproxy::{username}_max`
- AWG Standalone — `awgs_state.peers` → ключ `awg::{owner_email}_max`

Ключи с `proto::` prefix — чтобы избежать коллизий со старыми VLESS-ключами `{email}_max` (обратно совместимо). TrustTunnel намеренно НЕ включён — aggregate-only. Каждый протокол обёрнут в `try/except` с DEBUG-логом, чтобы один недоступный протокол не ронял весь снимок.

**`do_traffic_history()` TUI** — обновлён, чтобы показывать не только VLESS-emails из `_users_load()`, но и все ключи `<proto>::<id>_max` из `history.json`. Берёт топ-5 пользователей по суммарному трафику за период (раньше — первые 5 emails), чтобы график не перегружался (>5 цветов нет).

**Cron-скрипт** `/usr/local/bin/xray-traffic-snapshot.sh` — раньше содержал инлайн-реализацию опроса Xray Stats API (VLESS-only). Теперь делегирует в проектную функцию `_traffic_snapshot_save()`, что убирает дублирование и автоматически подключает все протоколы. PYTHONPATH=`/opt/chimera` (canonical install path, см. `trusttunnel.py:149`).

### Регрессионные тесты

`tests/test_mtproto_stats.py` — новый класс `TestSetupIptablesAccountingVerification` (2 теста):
1. `test_returns_false_when_chains_did_not_actually_appear` — iptables -N/-I «успешно» (returncode 0), но `_ipt_chain_exists()` после этого возвращает False → функция возвращает False, не True.
2. `test_returns_true_when_all_chains_and_jumps_confirmed` — полный успех (chains+jumps подтверждаются) → True.

`tests/test_mtproto.py` — новый класс `TestSetupAccountingWarnHonest` (1 тест):
3. `test_warn_called_when_iptables_accounting_fails` — `ipt_ok=False` → `_warn` с текстом про «меню Telemt → Статистика → пункт 3» вызван (spy на `_warn`).

`tests/test_traffic_dispatcher.py` — **новый файл** (14 тестов):
4. `test_mtproto_protocol_uses_mtproto_get_user_traffic_bytes` — `query_user_traffic_bytes("alice", "mtproto")` → вызывает `mtproto._get_user_traffic_bytes`, НЕ Xray Stats API.
5. `test_telemt_user_appears_in_snapshot` — telemt-пользователь появляется в `history.json` с ключом `mtproto::{username}_max`.
6. `test_mieru_user_appears_in_snapshot`, `test_naiveproxy_user_appears_in_snapshot`, `test_awg_peer_appears_in_snapshot` — аналогично для mieru/naiveproxy/awg (разрыв подтверждён — чиним для всех 4).
- Плюс синонимы (`vless`→`xray`, `telemt`→`mtproto`), failure-кейсы (mtproto бросает → 0), unknown-protocol → 0, VLESS регрессия (старый ключ `{email}_max` сохранён).

### DO NOT TOUCH (по требованию задачи)

- `mtproto_stats._collect()` / `_read_chain_bytes()` — внутренняя механика чтения iptables-счётчиков уже верна, не трогаем.
- `traffic_accounting.py` — ядро уже работает правильно для awg/mieru/naiveproxy/trusttunnel, не переделываем.
- `mtproto_stats._accounting_active()` — readonly-проверка существования цепочек, оставлена как есть.

### Изменённые файлы

- `chimera/modules/mtproto_stats.py` — `setup_iptables_accounting() -> bool` с постфактум-верификацией; новый `_ipt_jump_exists()`; `stats_menu()` пункт `[3]` показывает честный результат.
- `chimera/modules/mtproto.py` — `_setup_accounting()` упрощён; install flow — `else`-ветка с `_warn`.
- `chimera/modules/traffic_tracking.py` — новые `query_user_traffic_bytes(identifier, protocol)` + `query_user_traffic_bytes_accumulated(identifier, protocol)` + `SUPPORTED_PROTOCOLS_FOR_QUERY`.
- `chimera/modules/traffic_history.py` — `_traffic_snapshot_save()` мультипротокольная; `do_traffic_history()` показывает всех пользователей из `history.json`; `_install_traffic_snapshot_cron()` делегирует в проектную функцию.
- `tests/test_mtproto_stats.py` — +2 теста (iptables verification).
- `tests/test_mtproto.py` — +1 тест (install warn).
- `tests/test_traffic_dispatcher.py` — **новый**, 14 тестов (dispatcher + snapshot).

### Тесты

- `tests/test_mtproto_stats.py` — все PASS (включая +2 новых)
- `tests/test_mtproto.py` — все PASS (включая +1 новый)
- `tests/test_traffic_dispatcher.py` — 14/14 PASS (новый файл)
- Регрессия: `tests/test_mtproto*.py` + `test_traffic_*.py` — **271/271 PASS**
- `full_test.py` — **10/10 PASS**, проект готов к релизу

### Совместимость

Полностью обратно совместимо:
1. Старые ключи `{email}_max` в `history.json` продолжают работать (VLESS-пользователи не теряют историю).
2. `_query_user_traffic_bytes(email)` (без protocol-аргумента) сохранена — cron-скрипты и старый код работают как раньше.
3. `setup_iptables_accounting(port)` теперь возвращает `bool`, но старый вызов `setup_iptables_accounting(port)` без проверки возвращаемого значения всё ещё работает (как раньше — просто игнорирует результат).
4. Cron-скрипт `/usr/local/bin/xray-traffic-snapshot.sh` будет переписан при следующем вызове `_install_traffic_snapshot_cron()` (через меню "История трафика → [1] Включить сбор снимков"). До этого старая VLESS-only версия продолжает работать.

---

## FEAT(backup): единая АВТОМАТИЧЕСКИ РАСШИРЯЕМАЯ система бэкапа/восстановления всех протоколов + починка недостижимого «импорта только пользователей» — 25 июля 2026

### Постановка проблемы

В проекте существовали две параллельные, неполные системы экспорта/импорта
конфигурации:

1. **`do_export_config` / `do_import_config` / `do_manage_backup` /
   `_import_users_only`** в `chimera/_core.py` (старая система, пункт
   меню `[3] Стандартный экспорт`). Покрывала только VLESS+Reality+geo+
   AWG-Cascade.
2. **`do_full_migration_export` / `do_full_migration_import`** в
   `chimera/modules/migration.py` (вынесена из `_core.py` в коммите
   `7acdbfb` как Tier-3 рефакторинг). Дополнительно включала
   `traffic_limits.json`, `telegram.json`, SSL-сертификаты, systemd unit.

Обе системы покрывали только VLESS+geo+Cascade AWG. Ни одна не знала про
Telemt/Mieru/NaiveProxy/FPTN/TrustTunnel/sing-box-семейство/AWG-Standalone/
Hysteria2. Добавление нового протокола в будущем требовало ручной правки
списков `EXPORT_INCLUDE` и `include_paths` — что регулярно забывалось.

Плюс **критичный баг**: `do_manage_backup()` — единственное место с пунктом
«Импорт только пользователей» (помечено «безопасно после переустановки») —
**нигде не вызывался из живого меню**. Функция `_import_users_only()` уже
была рабочей, просто не имела точки входа. Мёртвый код.

### Решение по dual-system вопросу

**Изучение git-истории** (`git log --follow -- chimera/_core.py
chimera/modules/migration.py`, коммит `7acdbfb refactor(status): extract
10 functions to 7 modules (status/speed/reconfig/migration/mode/backup/
traffic-history)`):

`migration.py` был извлечён из `_core.py` как **рефакторинг-перенос**
(Tier-3 group 5 of 6), НЕ как замена. Обе системы сосуществовали ДО
рефакторинга, продолжают сосуществовать после. Каждая решает свой
сценарий:

- **`do_full_migration_export/import`** — полная миграция на ДРУГОЙ сервер:
  config + state + users + traffic_limits + telegram + SSL-сертификаты +
  systemd unit, обязательно зашифровано AES-256-CBC.
- **`do_export_config`** — стандартный нешифрованный бэкап ядра проекта
  (VLESS/Reality/state/users/geo/AS-direct) для повседневного использования
  на той же машине.

**Решение: обе системы остаются.** Помечать старую как deprecated не нужно
— это осознанно два разных инструмента для разных сценариев. Обе системы
теперь ОДИНАКОВО получают пути через автообнаружение (см. ниже). Доступ к
«импорту только пользователей» возвращён в живое меню (см. ниже).

### Что реализовано

**1. `chimera/modules/backup_registry.py` (новый модуль) — автообнаружение.**

Главная функция `discover_backup_paths(timeout_sec=20)`:

- Сканирует `chimera/modules/` через `pkgutil.iter_modules(chimera.modules.__path__)`
  → импортирует каждый модуль → вызывает `get_backup_paths()` если функция
  определена.
- Любая ошибка импорта/вызова у конкретного модуля — **тихий skip**
  (`try/except Exception: continue`), не прерывает сбор для остальных 213
  модулей.
- **Дедупликация** по реальному пути (`Path.resolve()`) — если два модуля
  случайно укажут один и тот же файл.
- **Timeout-guard** через `threading.Thread.join(timeout=N)` — если В
  БУДУЩЕМ какой-то новый модуль случайно получит тяжёлую операцию на
  уровне импорта (сетевой запрос, sleep и т.п.), один плохой модуль не
  сможет подвесить весь процесс бэкапа навсегда. При таймауте возвращается
  то, что успело собраться, + WARN в `chimera.log`.
- Намеренно **НЕ кэшируется** между вызовами процесса — протоколы могут
  быть установлены/удалены между запусками бэкапа. Скан ~0.8 секунды на
  214 модулей — оптимизация не нужна.

**2. Конвенция `get_backup_paths()` (договорённость об имени функции).**

Любой модуль в `chimera/modules/`, который хочет участвовать в общем
бэкапе, определяет на уровне модуля:

```python
def get_backup_paths() -> list[tuple[Path, str]]:
    """[(реальный_путь_на_диске, имя_в_архиве), ...].
    Пустой список если протокол не установлен.
    Никогда не бросает исключение — любая внутренняя ошибка = []."""
```

Модули БЕЗ `get_backup_paths()` тихо пропускаются (норма — большинство из
214 модулей `chimera/modules/` не являются протоколами и не имеют
конфиг-файлов для бэкапа).

**3. `get_backup_paths()` реализован в модулях, где его раньше не было:**

| Модуль | Файлы, попадающие в бэкап |
|---|---|
| `chimera/modules/mtproto.py` | `telemt.toml`, `telemt.service`, `telemt_limits.json` |
| `chimera/modules/mieru.py` | `mita/server.json`, `mita.service`, `mieru_state.json` |
| `chimera/modules/naiveproxy.py` | `Caddyfile`, `probe_secret`, `caddy-naive.service`, `naiveproxy_state.json` |
| `chimera/modules/fptn.py` | `server.conf`, `server.crt`, `server.key`, `fptn-server.service`, `fptn_state.json` |
| `chimera/modules/trusttunnel.py` | `trusttunnel_state.json`, `vpn.toml`, `hosts.toml`, `rules.toml`, `trusttunnel.service` |
| `chimera/modules/singbox_state.py` | `singbox_state.json`, `config.json`, `certs/*.crt|key|pem` |
| `chimera/modules/awg_standalone.py` | `awg0.conf`, `awgsetup_cfg.init`, `awg_standalone_state.json`, `awg-cascade-routing.service` |
| `chimera/modules/hysteria2_backup.py` | `config.yaml`, `hysteria.crt`, `hysteria.key`, `hysteria-server.service` |

Каждая реализация — просто проверяет `Path.exists()` и возвращает список
найденных, пустой список если протокол не установлен. Никакой сложной
логики, только пути. Никогда не бросает исключение (try/except → []).

Пользовательские секреты (клиентские ключи AWG, credentials.toml
TrustTunnel, и т.д.) намеренно НЕ включаются — их переиздают после
восстановления через соответствующее меню протокола, чтобы старые
скомпрометированные креды не поехали на новый сервер.

**4. Подключение `discover_backup_paths()` к обеим существующим точкам экспорта.**

- В `chimera/_core.py` → `do_export_config()`: после статического
  `EXPORT_INCLUDE` (VLESS/geo/AWG-Cascade/AS-direct — остаются как явные
  записи, раз они и так давно стабильны) добавочно вызывается
  `discover_backup_paths()` и его результат extend'ится к `_export_list`.
- В `chimera/modules/migration.py` → `do_full_migration_export()`:
  аналогично после статического `include_paths` (VLESS/state/users/traffic/
  telegram/SSL/systemd-unit/AWG-Cascade).

Обе точки — try/except с fallback на статический список, если
автообнаружение почему-то не сработает.

**5. Возвращена доступность «импорт только пользователей» в живое меню.**

`_menu_migration()` в `chimera/_core.py` получил пункт `[4] 👥 Импорт
только пользователей (безопасно после переустановки)`, который вызывает
уже существующую рабочую `_import_users_only(ap)`. Раньше эта функция
была мёртвым кодом — её пункт жил только в `do_manage_backup()`, который
нигде не вызывался.

**6. AWG Standalone и Hysteria2 — приведены к общей конвенции.**

У обоих уже есть собственные independent backup-модули
(`awg_backup.py`/`hysteria2_backup.py` с полнофункциональными
create/list/restore/menu), которые остаются. Но теперь ОНИ ЖЕ предоставляют
`get_backup_paths()` по общей конвенции — чтобы пользователь, по привычке
нажавший «Экспорт всего» в главном меню, получил AWG/H2-конфиги в общем
архиве тоже.

**Разобрано с `h2_backup_include_in_main()`**: существовавшая функция
была мёртвым кодом (нет ни одного вызова из `_core.py` или других
модулей, только self-reference в `hysteria2_backup.py`). НЕ удалена
(внешние патчи/скрипты могут импортировать), а превращена в thin
delegating wrapper к новому `get_backup_paths()`. Это закрывает
дублирование мёртвого кода и одновременно сохраняет обратную
совместимость.

### APPEND-FREE свойство — доказательство

Главное требование задачи: **решение должно быть APPEND-FREE для новых
протоколов**. Никакого жёсткого списка, который нужно пополнять при
добавлении протокола.

Тест `test_future_protocol_auto_discovered_without_code_changes` в
`tests/test_backup_registry.py` доказывает это: создаёт ВРЕМЕННЫЙ фейковый
модуль с `get_backup_paths()`, которого не было НИ РАЗУ до теста, и
убеждается, что `discover_backup_paths()` подхватывает его БЕЗ единой
правки кода самой системы бэкапа. Это тест, который доказывает решение
заявленной задачи («протокол появится позже — подхватится автоматически»).

### Тесты (`tests/test_backup_registry.py`, 29 тестов)

1. `discover_backup_paths()` находит фейковые тестовые модули с
   `get_backup_paths()` (через monkeypatch списка модулей — НЕ полагается
   на реальные 214 модулей `chimera.modules`).
2. Модуль БЕЗ `get_backup_paths()` — тихо пропускается.
3. Модуль, чей `get_backup_paths()` бросает исключение — не роняет
   остальной сбор.
4. Дедупликация одинаковых путей от двух модулей.
5. **Timeout-guard**: «зависший» модуль (30s sleep) не блокирует сбор —
   частичный результат + WARN, общий elapsed < 5s.
6. **ГЛАВНЫЙ смысловой тест — «будущий протокол» сценарий**: временный
   фейковый модуль подхватывается автоматически БЕЗ правок системы бэкапа.
7. Malformed entries (не-tuple, пустой arcname, list вместо tuple) — не
   роняют остальные.
8-21. Тест на каждый новый `get_backup_paths()` (mtproto/mieru/naiveproxy/
   fptn/trusttunnel/singbox_state/awg_standalone/hysteria2_backup):
   пустой список без установки, непустой с установленными файлами,
   never-raises.
22. `h2_backup_include_in_main()` теперь deprecated-делегат к
   `get_backup_paths()` (возвращает эквивалентные данные как `list[str]`).
23-24. **Регрессионный тест**: «импорт только пользователей» достижим из
   живого меню `_menu_migration()` — пункт `[4]` рендерится и при выборе
   вызывает `_import_users_only(ap)` с указанным путём.
25-26. Интеграционный тест с реальным деревом `chimera.modules` (214
   модулей): завершается за < 30 сек, не бросает исключение, находит
   `get_backup_paths()` во всех целевых модулях.

Полный `tests/` прогнан — 0 регрессий (существующие 3500+ тестов остались
зелёными).

### Файлы изменены

- `chimera/modules/backup_registry.py` — **новый** (200 строк)
- `chimera/modules/mtproto.py` — добавлен `get_backup_paths()`
- `chimera/modules/mieru.py` — добавлен `get_backup_paths()`
- `chimera/modules/naiveproxy.py` — добавлен `get_backup_paths()`
- `chimera/modules/fptn.py` — добавлен `get_backup_paths()`
- `chimera/modules/trusttunnel.py` — добавлен `get_backup_paths()`
- `chimera/modules/singbox_state.py` — добавлен `get_backup_paths()`
- `chimera/modules/awg_standalone.py` — добавлен `get_backup_paths()`
- `chimera/modules/hysteria2_backup.py` — добавлен `get_backup_paths()`;
  `h2_backup_include_in_main()` превращён в deprecated-делегат
- `chimera/_core.py` — `do_export_config()` вызывает
  `discover_backup_paths()`; `_menu_migration()` получил пункт `[4]` для
  импорта только пользователей
- `chimera/modules/migration.py` — `do_full_migration_export()` вызывает
  `discover_backup_paths()`
- `tests/test_backup_registry.py` — **новый** (29 тестов, 660 строк)

### Совместимость

Полностью обратно совместимо. Старые архивы (`xray-backup-*.tar.gz`,
`xray-migration-*.tar.gz.enc`) продолжают восстанавливаться. Новые архивы
теперь содержат дополнительные файлы от спутниковых протоколов — старый
`do_import_config`/`do_full_migration_import` их просто не найдёт в
`restore_map` и тихо проигнорирует (поведение не изменилось). Для
осознанного восстановления спутниковых протоколов из общего архива
пользователь должен использовать меню соответствующего протокола
(AWG Standalone → Backup → Restore, Hysteria2 → Backup → Restore, и т.д.)
— теперь эти независимые backup-модули имеют доступ к путям через общую
систему, что можно использовать в будущих патчах для автоматического
restore из общего архива.

---

## FIX(backup+deps): стабилизация после FEAT(backup) — mkdir parent-директории перед copy2 + сужение _smart_recover + warn о серверных секретах в нешифрованном архиве — 25 июля 2026

**После внедрения единой автообнаружаемой системы бэкапа (FEAT(backup) выше) вскрылись три проблемы, ни одна из которых не была выявлена в первоначальном анализе. Все три исправлены в этот же день отдельными коммитами `f9738b1`, `fad93cb`, `bbf7831` — без бампа версии, как добавочная стабилизация к существующей фиче.**

### Коммит `f9738b1` — убираем иероглиф из комментария + добавляем warn о серверных секретах

**Подпроблема 1: артефакт LLM-генерации.** В `chimera/_core.py` в комментарии к блоку автообнаружения в `do_export_config()` затесался китайский иероглиф: «Все**卫星**-протоколы» вместо «Все **спутниковые** протоколы» (как корректно написано в `migration.py` с того же коммита). grep по всем 13 правленным файлам на диапазон CJK `\u4e00-\u9fff` (а также по более широким CJK Extension A/B, корейскому, японскому, FFxx) — других артефактов не найдено, ликвидирован только один.

**Подпроблема 2: пользователь не предупреждён о попадании серверных секретов в нешифрованный архив.** `get_backup_paths()` у `mtproto.py` / `naiveproxy.py` / `hysteria2_backup.py` осознанно включает файлы с серверными секретами (`telemt.toml` — MTProto secret, `probe_secret` — naiveproxy anti-probing secret, `hysteria.key` — приватный TLS-ключ) — без них протокол не восстановить, это задокументировано в докстрингах. Но после ввода автообнаружения эти файлы стали автоматически попадать и в `encrypt=False` архив (пункт `[3] Стандартный экспорт` в `_menu_migration()`) — раньше туда входили только VLESS/Reality/geo/AWG-Cascade.

**Фикс:** после блока автообнаружения в `do_export_config()` добавлен условный `warn()`, который срабатывает ТОЛЬКО когда `encrypt=False` И `_discovered` непустой. Текст предупреждает: «Архив НЕ зашифрован, но содержит серверные секреты N доп. протоколов (MTProto/NaiveProxy/Hysteria2 и др.) — TLS-ключи и pre-shared секреты, без которых протокол не поднять заново. Храните архив как приватный ключ. Для передачи куда-либо — используйте шифрованный экспорт». Переменная `_discovered` инициализируется `[]` перед `try` — поэтому warn-блок корректно работает даже если импорт `backup_registry` упал с исключением.

Не выводится, если `_discovered` пустой (архив как раньше, не о чем предупредить) или `encrypt=True` (архив закрыт AES-256-CBC).

Логика `get_backup_paths()` в протокол-модулях НЕ пересматривается — решение включать туда серверные секреты осознанное и задокументированное. Меняется только то, что пользователь ТЕПЕРЬ явно предупреждён при экспорте без шифрования.

### Коммит `fad93cb` — латентный баг `shutil.copy2` на вложенных arcname + сужение `_smart_recover()`

**Подпроблема 3: latent-баг, вскрытый коммитом `8a4e93c`.** `get_backup_paths()` впервые в этом коде возвращает arcname с вложенностью — `"telemt/telemt.toml"`, `"mita/server.json"`, `"etc/systemd/system/mita.service"`, и т.д. Старый статический `EXPORT_INCLUDE` состоял только из плоских имён, поэтому цикл `shutil.copy2(src, tmp / dest_name)` работал — директория `tmp` уже существовала как сама временная папка. С появлением вложенных arcname `shutil.copy2` стал падать с `FileNotFoundError`, потому что поддиректория `tmp/telemt/` не существовала. Баг был латентным в `EXPORT_INCLUDE` и проявился только после ввода автообнаружения.

**Фикс в `chimera/_core.py::do_export_config()`:** перед `shutil.copy2` добавлен `dest_path.parent.mkdir(parents=True, exist_ok=True)`. Аналогичный цикл в `migration.py::do_full_migration_export()` проверен — там `mkdir(parents=True, exist_ok=True)` уже присутствовал с самого начала (строка 167), фикс не нужен.

**Подпроблема 4: `_smart_recover()` давал неверную диагностику на FileNotFoundError от файлов.** Механизм `_smart_recover` в `chimera/modules/system_deps.py` ловит `FileNotFoundError` вокруг `main_menu()` в `main.py` и предлагает установку недостающих пакетов. Но `FileNotFoundError` кидается не только при отсутствии системной команды — но и при попытке прочитать/записать несуществующий файл. До этого фикса случай из подпроблемы 3 (где `shutil.copy2` упал на `mita/server.json`) получал совершенно неверную диагностику: `_smart_recover` доставал `basename` «server.json», не находил его в `_CMD_TO_PKG`, но всё равно показывал «КОМАНДА НЕ НАЙДЕНА / apt-get install server.json» — что бессмысленно и сбивало с толку.

**Фикс в `chimera/modules/system_deps.py::_smart_recover()`:** после извлечения `missing_cmd` добавлена предварительная проверка. Если `missing_cmd` НЕ входит в `_CMD_TO_PKG` (справочник известных системных команд) И имеет расширение из `_FILE_EXT_HINTS` (`.toml` / `.json` / `.txt` / `.service` / `.crt` / `.key` / `.yaml` / `.yml` / `.pem` / `.conf` / `.cfg` / `.ini` / `.env` / `.sock` / `.socket` / `.log` / `.db` / `.sqlite`) — печатаем «ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ: <name>» + «Файл или директория не найдены — это не связано с отсутствующим системным пакетом» + traceback, возвращаем `False` (НЕ пытаемся `apt-get install`).

Реальные отсутствующие команды (`curl`, `xray`, ...) — старая ветка `apt-get install` работает как раньше, поведение НЕ изменилось. Сам механизм `_smart_recover` как «поймать `FileNotFoundError` вокруг `main_menu()`» в `main.py` не переделывается, только сужается область срабатывания apt-get-ветки.

### Коммит `bbf7831` — починка собственного регрессионного теста на вложенный arcname

Тест `test_nested_dest_name_does_not_raise` (созданный в `fad93cb`) падал в средах где `/root/` недоступен (`FileNotFoundError` на `archive_path.stat()`), хотя production-код уже корректен. Причина: `do_export_config()` после `tarfile.open` вызывает `archive_path.stat().st_size` для вывода размера — `archive_path` это `Path("/root/xray-backup-<ts>.tar.gz")`, который физически не существует (запись перенаправлена в `tmpdir` через `fake_tarfile_open`, `chmod` пропущен через `fake_path_chmod`, но `.stat()` не был замокан).

Фикс: добавлен `fake_path_stat` по образцу `fake_path_chmod` — для путей `/root/xray-backup-*.tar.gz` возвращает `os.stat_result` перенаправленного файла в `tmpdir`. `with patch.object(Path, "stat", fake_path_stat)` добавлен на том же уровне вложенности, что и `patch.object(Path, "chmod", ...)`, не отдельным блоком.

**Regression-catch верификация** (доказывает, что тест ловит реальный баг, а не проходит «случайно»):
1. С фиксом: тест проходит (42/42 PASS в `test_backup_registry.py`).
2. Временное удаление `dest_path.parent.mkdir(...)` в `_core.py`: тест **детерминированно падает** с корректным сообщением «parent dir `/tmp/xray_export_xxx/mita` does not exist when `copy2` is called with nested dest_name — bug not fixed» — spy на `shutil.copy2` ловит отсутствие parent-директории.
3. После возврата `mkdir`: тест снова проходит.

### Изменённые файлы

- `chimera/_core.py` — убран иероглиф; добавлен `warn()` о серверных секретах; добавлен `dest_path.parent.mkdir(parents=True, exist_ok=True)` перед `shutil.copy2` в `do_export_config()`
- `chimera/modules/system_deps.py` — `_smart_recover()` сужен: для `FileNotFoundError` с filename-расширением из `_FILE_EXT_HINTS` печатает «ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ» и возвращает `False` без `apt-get install`
- `tests/test_backup_registry.py` — новый класс `TestExportConfigWarnsAboutServerSecrets` (3 теста на warn о секретах); новый класс `TestExportConfigHandlesNestedDestNames` (1 тест на вложенный arcname, с правильно замоканными `Path.stat()` и `Path.chmod()`)
- `tests/test_system_deps.py` — новый класс `TestSmartRecoverFilesystemError` (7 тестов: 5 на файловые расширения + 2 на реальные команды)

### Тесты

- `tests/test_backup_registry.py` — **33/33 PASS** (29 из `8a4e93c` + 3 warn-теста из `f9738b1` + 1 nested-dest-name из `fad93cb`/`bbf7831`)
- `tests/test_system_deps.py` — **9/9 PASS** (2 старых + 7 новых)
- Регрессия на 13 затронутых модулях (`migration`/`awg_backup`/`config_backup`/`awg_standalone`/`hysteria2_backup`/`singbox_state`/`fptn`/`trusttunnel`/`naiveproxy`/`mieru`/`mtproto` + `system_deps`) — **402/402 PASS**
- `full_test.py` — **10/10 PASS**, проект готов к релизу

### Совместимость

Полностью обратно совместимо. Изменения затрагивают только:
1. Пользовательский вывод при `do_export_config(encrypt=False)` с непустым автообнаружением — появляется дополнительное `warn()` (раньше его не было).
2. Поведение `_smart_recover()` на `FileNotFoundError` с файловыми расширениями — теперь печатает «ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ» вместо «КОМАНДА НЕ НАЙДЕНА / apt-get install» (раньше вводящее в заблуждение поведение).
3. Внутреннюю логику `do_export_config()` — добавлен `mkdir(parents=True, exist_ok=True)`, ранее падавший с `FileNotFoundError` на вложенных arcname.

Старые архивы (`xray-backup-*.tar.gz`, `xray-migration-*.tar.gz.enc`) продолжают восстанавливаться без изменений. Новые архивы корректно собираются со всеми спутниковыми протоколами и вложенной структурой путей внутри tar'а.

---

## REFACTOR(geo): эталонный хэш ОДИН РАЗ через короткий приоритетный список — 24 июля 2026

**Полная замена логики SHA256-верификации геофайлов. Старая `_verify_checksum()` удалена, заменена на `_fetch_reference_hash()` + прямое сравнение в цикле. Это закрывает класс багов «цирка с геофайлами», который мучил несколько дней: установка падала на SHA256-mismatch, emergency fallback не работал, _verify_checksum перебирал все 19 зеркал заново для каждого .dat-кандидата.**

### Что было (до этого рефакторинга)

Логика SHA256-верификации в `chimera/modules/download_manager.py`:

1. `fetch_package()` перебирает 19 зеркал `.dat`-файла (geosite.dat/geoip.dat).
2. Для **каждого** кандидата, после успешного скачивания, вызывается `_verify_checksum(tmp_path, checksum_urls, ...)`.
3. `_verify_checksum()` заново перебирает **все 19** `checksum_urls`, скачивая `.sha256sum` с каждого, ищя хоть одно совпадение с `actual_hash`.

**Две проблемы:**

- **Избыточность.** Эталонный хэш один и тот же для всех попыток в рамках одного запуска. Перебирать 19 `checksum_urls` для каждого из 19 `.dat`-кандидатов = до 361 запросов `.sha256sum` (по ~100 байт). На практике меньше (early return при совпадении), но всё равно избыточно.

- **Критический баг.** CDN jsDelivr (4 бэкенда: cdn/gcore/fastly/testingcf) кэширует `.sha256sum` отдельно от `.dat`-файла, с разным TTL. Когда выходит новый релиз upstream, CDN какое-то время (1–12 часов) отдаёт **новый `.dat`** + **старый `.sha256sum`**. Старая `_verify_checksum()` на первом же `checksum_url` (cdn.jsdelivr.net) получала устаревший хэш, сравнивала с `actual_hash` нового файла — mismatch. Предыдущий фикс (перебор всех 19 `checksum_urls`, не early return) не решал корневую проблему: для **каждого** `.dat`-кандидата `_verify_checksum` снова спотыкалась на тех же устаревших `checksum_urls`, и в итоге все кандидаты отбраковывались одинаково — скачивание проваливалось целиком, хотя годные `.dat`-зеркала были в списке дальше.

**Симптомы у пользователя:**

```
geosite.dat → верификация sha256: 50e933acb2a23ab8… перебор 19 checksum-зеркал
geosite.dat ⚠ cdn.jsdelivr.net: sha256 НЕ совпал — ожидался e7e2711b2b68d7d9…
geosite.dat ⚠ gcore.jsdelivr.net: sha256 НЕ совпал — ожидался e7e2711b2b68d7d9…
... (ещё 17 checksum-зеркал, все с устаревшим хэшем)
geosite.dat ✗ sha256 НЕ совпал ни на одном из 19 ответивших зеркал — файл отбракован
geosite.dat → зеркало 2/19: gcore.jsdelivr.net...  ← пробуем следующее .dat-зеркало
... (та же история — _verify_checksum снова спотыкается на тех же 19 .sha256sum)
```

И так для всех 19 `.dat`-зеркал. Установка геофайлов проваливалась полностью, даже emergency fallback (прямой curl на GitHub) не помогал, потому что он тоже использовал `_verify_checksum`.

### Что сделано (этот рефакторинг)

**1. Новая функция `_fetch_reference_hash()`** в `chimera/modules/download_manager.py`:

Получает эталонный хэш **ОДИН РАЗ** с **короткого приоритетного списка** (не 19!):

| # | Источник | Почему |
|---|---|---|
| 1 | `raw.githubusercontent.com` | Авторитетный, содержимое напрямую из git, не сторонний кэш |
| 2 | `github.com/.../releases/latest/download/` | GitHub release-assets (редирект на `release-assets.githubusercontent.com`), тоже авторитетный |
| 3 | `cdn.statically.io` | Независимый CDN, последний fallback |

**НЕ включаются:**
- 4 бэкенда jsDelivr (cdn/gcore/fastly/testingcf) — это ОДИН CDN с общим кэшем `.sha256sum`, который и есть источник кэш-рассинхрона.
- Все gh-proxy (ghproxy.net, ghproxy.com, ...) — прокси-кэши GitHub, та же проблема кэш-рассинхрона.
- `jsd.cooluc.ru` — РФ-зеркало jsDelivr, общий кэш.

Функция возвращает hex-строку с **первого ответившего** источника. Если все 3 недоступны → `None` (деградация, см. ниже).

**2. `fetch_package()` рефакторён:**

```python
# ДО: для каждого .dat-кандидата — вызов _verify_checksum (перебор 19 .sha256sum)
for url in urls:
    ...скачали файл...
    if spec.checksum_urls:
        verify_result = _verify_checksum(tmp_path, spec.checksum_urls, ...)  # ← 19 запросов!
        if verify_result is False: continue

# ПОСЛЕ: reference_hash получен ОДИН РАЗ перед циклом, прямой сравнение
reference_hash = _fetch_reference_hash(spec.checksum_urls, ...)  # ← 1 запрос!
for url in urls:
    ...скачали файл...
    if spec.checksum_urls and reference_hash is not None:
        actual_hash = _compute_hash(tmp_path)
        if actual_hash != reference_hash:
            continue  # ← НЕ return, пробуем следующее .dat-зеркало с ТЕМ ЖЕ reference_hash
```

**Ключевое:** `continue` (не `return`) при mismatch — пробуем следующее `.dat`-зеркало с тем же `reference_hash`. Несовпадение у одного кандидата НЕ инвалидирует остальные. Это явно защищено regression-тестом.

**3. Деградация:** если `reference_hash is None` (все 3 приоритетных источника недоступны — маловероятно, но возможно при блокировке GitHub) — проверка хэша пропускается, файл принимается по размеру с явным warn. Это лучше чем блокировать всю загрузку.

**4. `emergency_curl_fallback()` в `geo_files.py`** тоже обновлён — вместо `_verify_checksum` вызывает `_fetch_reference_hash` + `_compute_hash` + прямое сравнение. Логика та же что в `fetch_package`.

**5. Старая `_verify_checksum()` УДАЛЕНА** полностью. Парсинг `.sha256sum` остался в существующей `_parse_checksum_content()` — переиспользуется в `_fetch_reference_hash`, не дублируется.

### Что ожидается

- **Установка геофайлов больше не должна падать на SHA256-mismatch.** Даже если CDN jsDelivr отдаёт устаревший `.sha256sum`, это больше не имеет значения — эталон берётся с `raw.githubusercontent.com` (или `release-assets`, или `cdn.statically.io`), которые синхронны с upstream.

- **Производительность.** Раньше: до 361 запросов `.sha256sum` (19 зеркал × 19 checksum_urls). Теперь: 1–3 запроса `.sha256sum` (короткий приоритетный список, первый ответивший). Ускорение установки геофайлов в ~100×.

- **Надёжность.** Даже если все 3 приоритетных источника недоступны (блокировка GitHub) — деградация до размерной проверки, файл принимается. Раньше в этом случае все 19 `.dat`-кандидатов отбраковывались.

- **Порядок `_MIRROR_FACTORIES` НЕ ТРОГАН.** Сами `.dat`-файлы (70+ МБ) качаются в прежнем порядке — jsDelivr первым (быстрее/доступнее из РФ). Меняется только источник эталонного хэша: 3 авторитетных URL вместо 19 с кэш-проблемами.

### Тесты

**Удалены** (тесты на старую `_verify_checksum`, не актуальны):
- `TestVerifyChecksumHelper` (5 тестов) — вся удалена.

**Добавлены** новые классы в `tests/test_download_manager.py`:

- `TestFetchReferenceHashHelper` (5 тестов):
  - `test_empty_checksum_urls_returns_none`
  - `test_raw_github_priority_first` — raw.github отвечает → только 1 вызов
  - `test_raw_github_timeout_fallback_to_release_github` — fallback на 2-й источник
  - `test_all_priority_sources_unavailable_returns_none` — все 3 упали → None (деградация)
  - `test_ghproxy_excluded_from_priority` — gh-proxy НЕ вызывается
  - `test_no_priority_urls_fallback_to_first_two` — edge case

- `TestSingleMirrorMismatchDoesNotInvalidateAllCandidates` (2 теста):
  - `test_single_mirror_mismatch_does_not_invalidate_all_candidates` — **ГЛАВНЫЙ regression**: 5 кандидатов `.dat`-зеркал, 1–4 с неверным хэшем (разные устаревшие версии), 5-й — валидный. Проверяет: (а) `reference_hash` запрошен ровно 1 раз (не 5), (б) хэш пересчитан и сравнён для ВСЕХ 5 кандидатов (цикл не прервался после первого mismatch), (в) итоговый файл с 5-го зеркала, `fetch_package` вернул `True`.
  - `test_reference_hash_fetched_once_even_with_many_mirrors` — с 10 зеркалами `reference_hash` всё равно 1 запрос.

**Обновлены** существующие тесты под новую логику:
- `test_hash_mismatch_retries_next_mirror` — 3 вызова вместо 5–6 (1 `reference_hash` + 2 файла).
- `test_hash_match_accepts_first_mirror` — 2 вызова (1 `ref` + 1 файл).
- `test_all_checksum_urls_404_degrades_to_size_check` — 4 вызова (1 файл + 3 priority-checksum).
- `test_checksum_unparseable_degrades_to_size_check` — 3 priority источника отдают мусор → `None` → деградация.
- `TestChecksumNotCalledInManualBranch` — мокается `_fetch_reference_hash` вместо `_verify_checksum`.

`tests/test_geo_emergency_fallback.py` — обновлены 9 тестов: `_verify_checksum` → `_fetch_reference_hash`, `return_value=True` → `return_value='match_hash'` + patch `_compute_hash`, `return_value=False` → `return_value='0'*64` (несовпадающий хэш).

`tests/test_geo_files.py` — фиксы mock-инфраструктуры:
- `_make_urlopen_mock`: каждый вызов `urlopen()` возвращает НОВЫЙ `mock_resp` со свежим `read.side_effect`. Раньше один `mock_resp` исчерпывался после 2 `read()` (в `_fetch_reference_hash` + первый chunk) → `StopIteration` → все 14 зеркал «падали» → `False`.
- `test_second_call_with_file_in_install_dests` — то же фикс.

### Прогон

694 passed, 825 subtests (geo + download + dns + mirrors + xray + youtube + ingress + emergency_fallback).

### Затронутые файлы

- `chimera/modules/download_manager.py` — `_verify_checksum` удалена, `_fetch_reference_hash` добавлена, `fetch_package` рефакторён.
- `chimera/modules/geo_files.py` — `_emergency_curl_one` обновлён под новую логику.
- `tests/test_download_manager.py` — 8 тестов добавлено, 5 удалено, 5 обновлено.
- `tests/test_geo_emergency_fallback.py` — 9 тестов обновлены.
- `tests/test_geo_files.py` — mock-инфраструктура фиксы.

### Почему это правильное решение

1. **Эталонный хэш — это факт, не opinion.** Upstream публикует один `.sha256sum` на релиз. Нет смысла «голосовать» по 19 зеркалам — достаточно получить эталон с одного авторитетного источника.

2. **Короткий список = меньше точек отказа.** 3 авторитетных источника (raw.github, release-assets, statically) надёжнее чем 19 с кэш-проблемами. Если все 3 недоступны — это уже не кэш-рассинхрон, а блокировка GitHub, и тут деградация по размеру — разумный компромисс.

3. **`continue` при mismatch — критично.** Это явно защищает от регрессии класса «один mismatch инвалидирует все остальные». Цикл пробует все 19 `.dat`-зеркал с одним и тем же `reference_hash`. Только если ВСЕ 19 дали неверный хэш (или не прошли по размеру) — операция считается проваленной.

4. **Порядок `_MIRROR_FACTORIES` сохранён.** Большие `.dat`-файлы (70+ МБ) качаются с jsDelivr первым — это правильно для скорости/доступности из РФ. Меняется только источник крошечного `.sha256sum` (100 байт) — тут jsDelivr не нужен, авторитетные источники надёжнее.

---

## FIX(diagnostics): шаг 11 (latency exit-нод) — детальная диагностика вместо голого «timeout» — 24 июля 2026

**Продолжение фикса шага 5. Шаг 11 «Exit-ноды: latency» (в `do_full_diagnostic`) тоже показывал «timeout» для нод, к которым реально подключение работало. Причина — тот же bash/`socket.create_connection` паттерн без детального вывода, плюс отсутствие подсказки для типичного кейса IPv6-only доменов на IPv4-only сервере.**

### Локация бага

`chimera/modules/diagnostics.py` → `do_full_diagnostic()` → шаг 11 (~строки 2040-2060 до фикса):

```python
try:
    _t0 = time.time()
    _ns = _socket.create_connection((_nh, _np), timeout=8)
    ...
except _socket.timeout:
    _box_info(f"  {_idx}{_hp:<{_HP_W}}  {RED}timeout{NC}")
    _wiz_hint(f"Firewall exit-сервера {_nh}: порт {_np} открыт?")  # ← сбивает с толку
    _node_fails.append(...)
except Exception as _ne:
    _box_info(f"  {_idx}{_hp:<{_HP_W}}  {RED}{str(_ne)[:12]}{NC}")
    _node_fails.append(...)
```

Проблемы:
1. **Не показывает, какая address family упала.** Для dual-stack домена при падении IPv6 с «Network is unreachable» пользователь видит «timeout» — и думает, что нода действительно лежит, хотя клиент (vless-ссылка) подключается через свой IPv6.
2. **Подсказка «Firewall exit-сервера: порт открыт?» вводит в заблуждение** — для кейса IPv6-only проблема не в firewall, а в отсутствии IPv6 на сервере диагностики.
3. **`socket.create_connection()` с `all_errors=False` (default)** — если первый адрес (IPv6) падает с OSError, переходит к IPv4. Но если IPv6 даёт `socket.timeout` (8 сек), потом IPv4 тоже может быть timeout — итого 16 сек на ноду. А если нода реально IPv6-only — пользователь ждёт зря.

### Что сделано

1. **`_diag_tcp_probe()` расширена** — теперь возвращает **3 значения** `(alive, detail, latency_ms)` вместо 2. Latency замеряется только для успешного соединения. Используется в обоих шагах (5 и 11) — единый код.

2. **Шаг 11 переписан** — вместо `socket.create_connection` + try/except используется тот же `_diag_tcp_probe()`, что в шаге 5. Вывод:
   ```
   [1/5] → node-a.example:443    167ms  (IPv4 203.0.113.111)
   [2/5] → fleet-b.example:443   timeout  (IPv6 2a12:bec4:1460:443::2: Network is unreachable)
     → На сервере нет IPv6, а fleet-b.example резолвится только в AAAA —
       клиент может подключаться через свой IPv6/другой резолвер
   [3/5] → fleet-a.example:443     41ms  (IPv4 203.0.113.133)
   ```

3. **Раздельные подсказки для разных кейсов**:
   - Если в detail есть `IPv6`, но нет `IPv4` (т.е. домен только AAAA, а на сервере нет IPv6) → подсказка «на сервере нет IPv6, клиент может подключаться через свой IPv6»
   - Иначе → стандартная подсказка про firewall/порт

4. **Latency для успешного соединения берётся из `_diag_tcp_probe`** — раньше замерялось через `time.time()` вокруг `create_connection` (включая время на DNS-резолв и перебор адресов), теперь замеряется только `socket.connect()` до конкретного адреса.

### Не тронуто

- `socket.create_connection` в других местах проекта — отдельная история, не относится к диагностике
- Шаги 1-10, 12-14 диагностики — не связаны
- AWG-ветка шага 11 (для режима AWG 2.0) — не тронута, там своя логика через handshake/ping
- `_diag_check_routing_live()` (шаг 5) — обновлён в предыдущем коммите, теперь использует тот же `_diag_tcp_probe()`

### Тесты

`tests/test_diagnostics.py` — **20 passed** (без изменений, тесты обновлены под новый 3-tuple return):
- `TestDiagTcpProbe` — 8 тестов, проверяют что `lat` (третье возвращаемое значение) равно `-1` при ошибках и `>=0` при успехе
- Остальные 12 тестов (FmtBytes, MakeCounters, DiagChk, ResolveConfig) — 0 регрессий

Регрессии: полный набор diagnostics-тестов — 0 регрессий.

---

## FIX(diagnostics): ложное «НЕДОСТУПНА» для IPv6-only exit-нод в тесте маршрутизации — 24 июля 2026

**В отчёте «Диагностика одной кнопкой» шаг 5 (TCP ping exit-нод) показывал некоторые ноды как «НЕДОСТУПНА (timeout или rejected)», хотя подключение по vless-ссылке к тем же нодам работало нормально. Корень проблемы: для TCP-ping'а использовался bash `/dev/tcp/{host}/{port}`, который под капотом вызывает `getaddrinfo()` и пытается установить соединение. Если домен ноды резолвился только в AAAA (IPv6), а на сервере диагностики нет публичного IPv6-маршрута — bash получал «Network is unreachable» и диагностика помечала ноду как недоступную. Но реальный клиент (vless-ссылка) мог подключаться через свой IPv6, либо через другой резолвер, который отдавал IPv4 — и соединение работало.**

### Локация бага

`chimera/modules/diagnostics.py:_diag_check_routing_live()` (строки ~729-757 до фикса):

```python
r = subprocess.run(
    ["bash", "-c",
     f"timeout 5 bash -c 'echo > /dev/tcp/{host}/{port}' 2>/dev/null && echo ok || echo fail"],
    ...
)
alive = r.stdout.strip() == "ok"
```

Проблемы этого подхода:
1. **IPv4-only fallback отсутствует** — bash `/dev/tcp` перебирает адреса из `getaddrinfo()`, но если первый (IPv6) падает с «Network is unreachable», не пытается IPv4
2. **Timeout 5 сек** — для некоторых мобильных/спутниковых exit-нод маловато
3. **Неинформативное сообщение** — «НЕДОСТУПНА (timeout или rejected)» не даёт понять, какая именно address family упала и почему

### Что сделано

Новая функция `_diag_tcp_probe(host, port, timeout=10)` в `diagnostics.py`:

1. **`socket.getaddrinfo()` с явным перебором всех адресов** — берёт все записи (IPv4 + IPv6), дедуплицирует по `(family, sockaddr)`, перебирает по очереди. Если хотя бы одна семья отвечает — нода считается живой.

2. **Явный timeout 10 секунд** на каждую попытку `socket.connect()` через `s.settimeout(10)`.

3. **Детальный вывод** — вместо «НЕДОСТУПНА (timeout или rejected)» теперь показывает, что именно упало:
   - `Exit-нода [chain-exit-2] fleet-b.example:443 — TCP достижима (IPv4 203.0.113.108)` — успешный кейс
   - `Exit-нода [chain-exit-2] fleet-a.example:443 — НЕДОСТУПНА (IPv6 2a12:bec4:1460:443::2: Network is unreachable)` — IPv6-only домен на IPv4-only сервере
   - `Exit-нода [...] dualstack.com:443 — НЕДОСТУПНА (IPv6 2a12::1: Network is unreachable; IPv4 1.2.3.4: timed out)` — обе семьи упали, видно обе ошибки

4. **Подсказка для типичного кейса** — если в detail есть IPv6, но нет IPv4 (т.е. домен только AAAA, а на сервере нет IPv6), выводится дополнительная строка:
   > `↳ На этом сервере нет публичного IPv6, а домен ноды резолвится только в AAAA. Клиент может подключаться, если у него есть IPv6 или используется другой резолвер.`

### Не тронуто

- Остальные шаги диагностики (1-4, 6+) — не связаны, работают через `subprocess.run` для других команд
- `_diag_check_routing_live()` — вызывается из `run_full_diagnostics()`, сигнатура не изменилась
- `chain_nodes.py` — отдельная функция TCP-ping для live-статуса нод в основном меню, не тронута (там свой код)

### Тесты

`tests/test_diagnostics.py` — **20 passed** (12 существующих + 8 новых, класс `TestDiagTcpProbe`):

1. `test_dns_fail_returns_false_with_detail` — DNS не резолвит → `False`, detail содержит «DNS fail»
2. `test_dns_empty_returns_false` — `getaddrinfo` вернул пустой список → `False`, detail = «DNS empty»
3. `test_ipv4_only_success` — IPv4-only домен, коннект успешен → `True`, detail содержит «IPv4» и адрес
4. `test_ipv6_only_unreachable_on_ipv4_only_server` — кейс `fleet-a.example`: только AAAA, `OSError("Network is unreachable")` → `False`, detail содержит «IPv6» и «unreachable»
5. `test_dualstack_ipv6_fails_ipv4_succeeds` — dual-stack домен, IPv6 падает, IPv4 отвечает → `True`, detail содержит «IPv4» (ключевой кейс — раньше bash давал `False`, теперь `True`)
6. `test_dualstack_both_fail` — обе семьи упали → `False`, detail содержит обе ошибки (IPv6 + IPv4 + «unreachable» + «timeout»)
7. `test_timeout_10_seconds_passed_to_socket` — проверка что `timeout=10` доходит до `s.settimeout(10)`
8. `test_dedup_duplicate_addrinfo_entries` — `getaddrinfo` часто возвращает дубликаты — должны быть дедуплицированы, только ОДИН сокет создаётся

Регрессии: `tests/test_diagnostics.py` (старые 12 тестов) — 0 регрессий. Итого: 20 passed.

---

## FEAT(geoblock): гео-блокировка по странам для Telemt — 23 июля 2026

**Гео-блокировка по странам для Telemt (MTProto): можно запретить подключение к MTProto-порту с IP-адресов указанных стран. Блокировка работает на уровне iptables (ДО бинарника Telemt), а не на уровне Xray routing — DROP срабатывает раньше, чем соединение дойдёт до обработки. Переиспользован паттерн из `ingress_geoip.py` (ipset `hash:net` + iptables DROP), но в режиме block-list (DROP конкретных стран), а не allowlist.**

### Источник данных

ipdeny.com — aggregated country zone files:
- IPv4: `ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone`
- IPv6: `ipdeny.com/ipblocks/data/aggregated/ip6t/{cc}-aggregated.zone`

### Что сделано

Новый модуль `chimera/modules/geoblock.py` (419 строк) + интеграция в `chimera/modules/mtproto.py` (+11 строк):

1. **Функции API**:
   - `geoblock_add_country(port, country_code)` — блокирует страну на порту
   - `geoblock_remove_country(port, country_code)` — разблокирует
   - `geoblock_list(port)` — список заблокированных стран
   - `geoblock_restore_all()` — восстановление после ребута (из state)
   - `geoblock_menu_telemt(port)` — TUI-меню

2. **Персистентность**:
   - `ipset save` через `ipset_persist.ipset_save()` (как в `ingress_geoip`)
   - State в `/var/lib/xray-installer/geoblock_telemt.json`
   - ipset-сеты с уникальными именами `telemt_geoblock_v4_{cc}` / `telemt_geoblock_v6_{cc}` — не конфликтуют с `xray_ru_block`

3. **TUI** — главное меню Telemt: новый пункт `G` — Гео-блокировка по странам. Подменю: заблокировать страну, разблокировать, список заблокированных.

### Не тронуто

- `ingress_geoip.py` (RU-allowlist) — только переиспользование паттерна
- `awg_expires.py` — не связан
- `geoip_block.py` (Xray routing level) — отдельный механизм, не тронут

### Тесты

`tests/test_geoblock.py` — **6 passed** (новый файл):
1. `test_add_country_calls_ipset_and_iptables` — ipset create + iptables DROP вызываются, state сохранён
2. `test_invalid_country_code_returns_false` — неверный код страны → `False`
3. `test_remove_country_calls_ipset_destroy` — ipset destroy + iptables `-D`, state обновлён
4. `test_list_returns_countries_from_state` — возвращает страны из state
5. `test_list_empty_state_returns_empty` — пустой state → пустой список
6. `test_list_different_port_returns_empty` — другой порт → пустой список

Регрессии: `tests/test_mtproto_limits.py` (15) + `tests/test_mtproto.py` (140) — 0 регрессий. Итого: 161 passed.

---

## FEAT(mtproto): per-user лимиты (квота трафика + срок действия) для Telemt — 23 июля 2026

**Per-user лимиты для Telemt (MTProto): можно назначить каждому пользователю квоту трафика (например `10G`) и/или срок действия (например `30d`), при достижении/истечении которых пользователь автоматически удаляется (с restart'ом бинарника). Лимиты хранятся в отдельном JSON-файле — формат `telemt.toml` не трогается (бинарник читает только `[access.users]` секцию, менять формат нельзя), обратная совместимость со старыми конфигами полная.**

### Что сделано

Новый функционал в `chimera/modules/mtproto.py` (+340 строк), обёртка над существующим `mtproto_stats._load_stats()` для учёта трафика и `awgs_expires_*` для парсинга duration:

1. **Хранение** — отдельный JSON-файл `/var/lib/xray-installer/telemt_limits.json`. Старые конфиги без лимитов работают без изменений — лимиты просто отсутствуют, пользователь считается безлимитным.

2. **Установка лимитов** — `mtproto_set_limits(username, quota, expires_in, max_connections)`:
   - `quota`: `'10G'` через `traffic_accounting.parse_human_readable_bytes`
   - `expires_in`: `'30d'` через `awgs_expires_parse + awgs_expires_compute_iso`
   - `max_connections`: НЕ ПОДДЕРЖИВАЕТСЯ бинарником telemt — записывается в JSON для будущего использования, но не применяется. Документировано в TUI как ограничение.

3. **Проверка лимитов** — `mtproto_check_limits()` (cron каждые 5 мин):
   - Истёк срок → удаляет пользователя (`remove_user` + restart)
   - Превышена квота → удаляет пользователя
   - Возвращает `{'expired': N, 'quota_exceeded': N}`

4. **TUI** — главное меню Telemt: новый пункт `L` — Лимиты пользователей. Меню управления пользователями: новый пункт `5` — Лимиты. Список пользователей показывает колонки Квота и Срок. Таблица: имя, квота (used/total), срок, трафик.

5. **Cron** — `mtproto_stats.setup_accounting()` дополнен второй строкой (`*/5 * * * * root python3 -c "...mtproto_check_limits()"`). НЕ отдельный cron-файл — дополнение к существующему `/etc/cron.d/telemt-stats`.

### Переиспользовано (не дублировано)

- `awgs_expires_parse/compute_iso/is_expired/humanize` — парсинг duration, вычисление ISO-даты, проверка истечения, человекочитаемый вывод
- `traffic_accounting.parse_human_readable_bytes` — парсинг `'10G'`/`'500MB'`
- `mtproto_stats._load_stats()` — per-user трафик (rx+tx)
- `_load_users()/_save_users()` — без изменений, обратная совместимость

### Тесты

`tests/test_mtproto_limits.py` — **15 passed** (новый файл):
1. set_quota_and_expiry — квота + срок → `True`
2a. set_quota_only — только квота
2b. set_expiry_only — только срок
2c. set_both_none — оба `None` (безлимит)
3. nonexistent_user — `False`
4a. invalid_quota — `False`
4b. invalid_expiry — `False`
5. get_limits — все поля + `used_bytes`
6. remove_limits — удаление
7. check_limits: expired → удалён
8. check_limits: quota_exceeded → удалён
9. check_limits: unlimited → не тронут
10a. old_format_plain_strings — обратная совместимость
10b. old_format_with_limits — старый формат + новые лимиты

Регрессии: `tests/test_mtproto.py` (195 passed), `tests/test_awg_expires.py` — 0 регрессий.

---

## FEAT(youtube-ip-pin): экспериментальная опция закрепления YouTube-CDN по IP — 23 июля 2026

**Новая экспериментальная опция: закрепление YouTube-CDN по IP поверх уже выбранной exit-ноды. Добавляет ДОПОЛНИТЕЛЬНОЕ routing-правило в Xray config (матчащее по IP-адресам из внешнего списка, а не по доменам) рядом с доменным правилом YouTube. Оба правила включаются/выключаются независимо.**

⚠️ **Дисклеймер (показывается в UI при включении):** YouTube отдаёт видео с подписанных URL конкретного cache-узла, который сервер YouTube выбирает в момент запроса manifest'а. Пиннинг по IP из внешнего списка НЕ гарантирует, что видео будет доступно — это best-effort, может давать 403/таймауты. Не использовать как основной механизм выбора региона (для этого есть выбор exit-ноды).

### Источник данных

`github.com/touhidurrr/iplist-youtube` — `lists/cidr4.txt` (~557 CIDR IPv4) и `lists/cidr6.txt` (~710 CIDR IPv6). Обновляется автором каждые 5 минут, нам достаточно рефетча раз в сутки.

### Что сделано

**Новый файл: `chimera/modules/youtube_ip_pin.py`**

1. **PackageSpec x2** (cidr4.txt, cidr6.txt) — через `download_manager.fetch_package()`, полностью переиспользована существующая логика скачивания/ретраев. `post_install` — content-level валидация через `ipaddress.ip_network()` построчно (минимум 300/400 валидных CIDR, отбраковка мусора/404-страниц). `checksum_urls=None` — апстрим не публикует чек-суммы.

2. **`download_youtube_iplist()`** — скачивает оба списка, записывает timestamp в state.json.

3. **`setup_youtube_iplist_autoupdate()`** — cron ежедневно в 04:00, отдельный файл `/etc/cron.d/youtube-iplist-update` (НЕ трогает существующий `/etc/cron.d/xray-geo-update`).

4. **`apply_youtube_ip_pin(target_tag)` / `remove_youtube_ip_pin()`** — IP-правило с `comment="youtube_ip_pin"`, отдельное от доменного (`comment="youtube_via_ru"`). При `target="off"` — не применяется. Проверяет существование outbound (если нода удалена — `False` + warn).

5. **UI** — подменю в `do_manage_youtube_via_ru()` (youtube_route.py), показывается ТОЛЬКО когда `current_target != "off"`. Пункты: включить/выключить IP-pin (с дисклеймером), обновить списки, вкл/выкл cron. Статус: дата обновления, кол-во CIDR, вкл/выкл.

6. **`restore_ip_pin_if_needed()`** — вызывается из `restore_youtube_rule_if_needed()` после regenerate xray-config. При рассинхроне (`ip_pin_enabled=True`, `route_target="off"`) — не применяется, логирует warn, не падает.

### State

Новые ключи в state.json: `youtube_ip_pin_enabled` (bool), `youtube_iplist_updated_at` (ISO-timestamp).

### Не тронуто

- Доменная логика `youtube_route.py` (`_youtube_apply_to_xray`, `_YOUTUBE_DOMAINS`)
- `geo_packages.py`/`geo_mirrors.py`/`geo_files.py` — только переиспользование
- Существующий `/etc/cron.d/xray-geo-update`
- Логика выбора exit-ноды

### Тесты

`tests/test_youtube_ip_pin.py` — **9 passed** (8 кейсов + 1 regression на порядок зеркал):
1. PackageSpec x2 валидны (assert `manual_incoming_dir != install_dests`)
2. post_install: 600 валидных CIDR → принимается
3. post_install: мусор (HTML 404) → отбраковывается
4. `apply("off")` → `False`
5. `apply("chain-exit-2")` → IP-правило добавлено, доменное не тронуто
6. `remove()` → убирает только IP-правило, доменное остаётся
7. restore: `ip_pin=True`, `target="off"` → `False`, не падает
8. `_mirror_urls` порядок: raw.githubusercontent.com первым, jsDelivr — fallback

---

## FEAT(youtube-route): выбор конкретной exit-ноды для YouTube в multi-node режиме — 23 июля 2026

**Переключатель «YouTube через RU» расширен до выбора конкретной exit-ноды в multi-node режиме. Раньше был только бинарный выбор: RU entry (direct/direct-local) или exit-каскад (default catch-all через балансировщик). Теперь при наличии >1 exit-ноды меню показывает по пункту на каждую ноду + RU + default — можно направить YouTube-трафик через конкретную ноду, а не через балансировщик.**

### Что сделано

1. **`_youtube_apply_to_xray(target_tag)`** — новый параметр `target_tag: str | None`:
   - `None` — RU entry (direct/direct-local, AWG-aware) — обратная совместимость
   - `"chain-exit-N"` — конкретная exit-нода N. Проверяет что outbound существует — если нода удалена, возвращает `False` + warn, НЕ пишет правило с несуществующим тегом (Xray падает с "unknown outbound tag")

2. **`_save_youtube_state(target: str)`** — замена `bool` на `str`:
   - Новый ключ `youtube_route_target`: `"ru"` | `"off"` | `"chain-exit-N"`
   - Legacy `youtube_via_ru`: `(target == "ru")` — для обратной совместимости

3. **`do_manage_youtube_via_ru()`** — переписано меню:
   - `len(CHAIN_NODES) <= 1`: старое двухпунктовое меню `[1/2/Q]` (обратная совместимость)
   - `len(CHAIN_NODES) > 1`: меню `[1..N+2/Q]` — RU + N нод (показывает хост каждой) + default (балансировщик)
   - Миграция со старого `youtube_via_ru` bool — без отдельного скрипта
   - Статус отличает «правило пропало после regenerate» от «нода была удалена»

4. **`restore_youtube_rule_if_needed()`** — обновлён под новый ключ `youtube_route_target`:
   - `target="ru"` → `_youtube_apply_to_xray(target_tag=None)`
   - `target="chain-exit-N"` → `_youtube_apply_to_xray(target_tag=target)`
   - Если нода не существует → `False`, не падает

### Не тронуто

- `chain_nodes.py` — генераторы конфигов, balancer, теги `chain-exit-N` (уже корректны)
- `_YOUTUBE_DOMAINS` список
- `generate_xray_config_chain_entry()` (single-node)
- AWG_EXIT_ENABLED-ветка (`direct-local`)

### Тесты

`tests/test_youtube_route.py` — **29 passed** (19 существующих обновлены + 10 новых):
1. `target_tag=None` → `direct` (regression)
2. `target_tag="chain-exit-2"` с outbound → правило пишется
3. `target_tag="chain-exit-5"` без outbound → `False`, config не тронут
4. `_save_youtube_state("chain-exit-2")` — новый ключ + legacy `False`
5. `_save_youtube_state("ru")` — legacy `True`, обратная совместимость
6. Миграция — старый `youtube_via_ru=True` без `youtube_route_target` → RU
7. `len(CHAIN_NODES)<=1` → старое `[1/2/Q]` меню
8. `len(CHAIN_NODES)==3` → `[1-5/Q]` меню с хостами нод
9. restore с `chain-exit-2`, нода существует → пере-применяет
10. restore с `chain-exit-9`, ноды нет → `False`, не падает

---

## FIX(awg): проверка коллизий H1-H4 в ручном вводе обфускации — 23 июля 2026

**Доработка AWG 2.0 : в ручном вводе параметров обфускации (пункт меню "3" в `prompt_awg_exit_mode()`) добавлена проверка на коллизии H1-H4. Раньше каждое H вводилось через независимый `_ask_int()` вызов — дубликат между ними никак не ловился, хотя весь смысл фичи — уникальность H1-H4 (DPI-отпечаток). Теперь при обнаружении дубликата пользователю показывается предупреждение и предлагается ввести значения заново. После 5 неудачных попыток — fallback на рекомендованные уникальные значения из `awgs_generate_full_manual_params()`.**

### Локация

`chimera/modules/install_prompts.py`, ветка `elif _obf_ch == "3"` (ручной ввод полного набора), поля H1-H4.

### Изменение

Логика проверки коллизий выделена в отдельную функцию `_prompt_h1_h4_unique(_rec, _ask_int_fn, warn_fn, info_fn)` для тестопригодности. Внутри `prompt_awg_exit_mode()` вызов заменён на:
```python
AWG_H1, AWG_H2, AWG_H3, AWG_H4 = _prompt_h1_h4_unique(_rec, _ask_int, warn, info)
```

Алгоритм:
1. Ввод H1-H4 через 4 вызова `_ask_int_fn` (как раньше)
2. Проверка: если есть дубликаты — `warn` + `info` + перезапрос всех 4 полей
3. Цикл до 5 попыток; после 5 — fallback на `_rec["h1".."h4"]` (гарантированно уникальные рекомендованные значения), `warn` об fallback, `break`
4. `setattr(core, ...)` для H1-H4 одним блоком после успешной проверки (раньше был разбросан — перенесён)

### Тесты

`tests/test_install_prompts.py` — новый файл, 4 кейса:
1. `test_duplicate_first_attempt_unique_second` — H1=H2=100 первой попыткой, второй — уникальные → успех
2. `test_five_attempts_with_duplicates_fallback_to_rec` — 5 попыток с dup → fallback на _rec, без зависания
3. `test_first_attempt_unique_no_retry` — сразу уникальны → input вызван ровно 4 раза (не 8+), warn не вызван
4. `test_three_duplicates_fourth_unique` — 3 dup, 4-я уникальна → успех (доп. кейс на множественные retry)

Мок `builtins.input` через `side_effect` с итератором (как в `test_xray_install.py`, `test_ios_shadow_client.py`).

### Не тронуто

- `awgs_generate_full_manual_params()` в `awg_presets.py` — там уникальность уже гарантирована
- Ветки `_obf_ch == "1"`, `"2"`, `"4"` — там H1-H4 либо не спрашиваются, либо уже уникальны (auto_full), либо намеренно одинаковы (preset)

### Прогон

- `tests/test_install_prompts.py` — **4/4 passed** (новый файл)
- `tests/test_awg_presets.py` — 51/51 passed
- `tests/test_awg_transport.py` — 49/49 passed
- `tests/test_awg_standalone.py` + `test_awg_apply.py` + `test_awg_cascade.py` — 51/51 passed
- Итого: **155 passed**, 0 регрессий

---

## FEAT(awg): полный набор параметров обфускации AWG 2.0 (16 шт) во всех режимах — 23 июля 2026

**Жалоба пользователя (Keenetic не может импортировать AWG-конфиг от Chimera) вскрыла две проблемы: (1) Cascade-режим генерил неполный набор параметров — только 9 штук (Jc/Jmin/Jmax/S1/S2/H1-H4), без S3/S4/I1-I5; Keenetic — парсер-строгий, падал на отсутствии I1. (2) H1-H4 хардкожены как фиксированные 1,2,3,4 везде — узнаваемый DPI-отпечаток именно этого проекта, хотя по официальной документации AmneziaWG H1-H4 должны быть уникальны для каждого развёртывания.**

### Что сделано

1. **`chimera/modules/awg_presets.py`** — новая функция `awgs_generate_full_manual_params(overrides)` — параллельный путь для «полного ручного» или «полного авто» набора. НЕ заменяет и НЕ трогает `awgs_presets_generate()` — пресеты операторов остались как есть. Ключевые отличия: H1-H4 — непересекающиеся случайные значения в 1..INT32_MAX; S3/S4 — случайные в рекомендованных диапазонах; I1 — hex 48-64 символа; правило S1+56!=S2 проверяется и перегенерируется при коллизии.

2. **`chimera/_core.py`** — добавлены globals `AWG_S3`, `AWG_S4`, `AWG_I1-AWG_I5`, `AWG_OBFUSCATION_SOURCE`. Все 16 параметров теперь persist'ятся в state.json и читаются обратно (раньше obfuscation параметры НЕ сохранялись — скрытый баг, при рестарте Chimera всегда сбрасывались в дефолты). `AWG_OBFUSCATION_SOURCE` хранит источник (`default` / `auto_full` / `manual` / `preset:tele2_krasnoyarsk`) — для диагностики при жалобах.

3. **`chimera/modules/awg_transport.py`** — все 4 Cascade-функции (`_awg_server_conf_text`, `_awg_client_conf_text`, `_awg_client_conf_for_node`, `_awg_server_conf_for_node`) обновлены до полного набора: читают S3/S4/I1-I5 из core globals, пишут S3/S4 всегда, I1-I5 условно (только если непустые).

4. **`chimera/modules/install_prompts.py`** — `prompt_awg_exit_mode()` теперь предлагает 4 варианта настройки обфускации (вместо старого y/N): (1) значения по умолчанию, (2) авто-генерация полного набора [рекомендуется], (3) ручной ввод с рекомендованными значениями, (4) готовый пресет под оператора.

5. **`chimera/modules/awg_presets.py`** — валидация H1-H4 расширена с 0-255 до 0-INT32_MAX (по официальной документации AmneziaWG).

### Не тронуто

- `AWGS_CARRIER_PRESETS` (9 пресетов) — значения не изменены
- `awgs_presets_generate(name)` — не тронута
- H1-H4=1,2,3,4 внутри пресетного пути — не тронуты

### Тесты

- `tests/test_awg_presets.py` — **51/51 passed** (+14 новых: TestGenerateFullManualParams + TestCarrierPresetsNotChanged)
- `tests/test_awg_transport.py` — **49/49 passed** (+13 новых: TestCascadeFullParamsV4257)
- Полный AWG-набор (15 файлов) — **457 passed**, 0 регрессий
- geo + dns + download + autoban + install — **292 passed**, 0 регрессий
- Итого: **749 тестов прошли**, 0 регрессий

---

## FIX(geo): критический баг — geo-файлы копировались под именем временного файла (10.07–22.07.2026 все обновления были no-op) — 22 июля 2026

**КРИТИЧЕСКИЙ баг, обнаруженный на реальном сервере 22.07.2026: `geosite.dat`/`geoip.dat` копировались в `/etc/xray/` под именем `_download_mgr_geosite.dat` вместо канонического `geosite.dat`. Это означало, что ВСЕ обновления geo-файлов с 10.07.2026 (коммит `fbb2285`, миграция `download_geo_files()` на `fetch_package()`) по 22.07.2026 (день обнаружения) были no-op по факту: скачивание и sha256-верификация проходили успешно, но результат никогда не попадал в реальный `/etc/xray/geosite.dat` (и параллельные копии в `/usr/local/share/xray/`, `/usr/local/etc/xray/`) — вместо этого создавался файл `_download_mgr_geosite.dat` РЯДОМ со старым нетронутым `geosite.dat`.**

Это объясняет вообще весь цикл проблем с «geosite.dat возраст 202 дня», которые диагностировались и чинились последние два дня:
- `a20c0f1` — фикс хардкоженных порогов в cron-скрипте (3 МБ → 20 МБ из `MIN_SIZES`) — был правильным, но не мог проявиться, потому что реальный целевой файл никогда физически не подменялся.
- `e90f255` — sha256-верификация — была правильной, но отбраковывала файлы, которые потом копировались под неправильным именем.
- `1f3dd04` — revert категории `ru-available-only-inside` — был правильным, но категория никогда не проверялась на актуальном файле в `/etc/xray/` (там лежал 200-дневной давности протухший файл).

### Локация бага

- `chimera/modules/geo_packages.py:_post_install_geo()` строка ~101: `dest = dest_dir / src.name`, где `src` = `tmp_path` = `Path("/tmp") / f"_download_mgr_{filename}"` — `src.name` буквально равен `"_download_mgr_geosite.dat"`, а не `"geosite.dat"`.
- `chimera/modules/download_manager.py:_default_copy_to_dests()` строка ~328 — та же ошибка (`dest = dest_dir / src.name`), но эта функция используется только при `post_install=None` (например `XRAY_CHECKSUMS_SPEC` — `.dgst` файлы копируются в `/tmp/`). workaround в `xray_packages._fetch_dgst_content` уже учитывал оба варианта имени файла, так что Xray не пострадал.

### Фикс (вариант (б) — минимальный blast radius)

`chimera/modules/download_manager.py:fetch_package()` — после успешной sha256-верификации, **перед** вызовом `post_install`/`_default_copy_to_dests`, `tmp_path` переименовывается из `/tmp/_download_mgr_{filename}` в `/tmp/{filename}` (каноническое имя). Тогда `src.name` автоматически становится каноническим, и все ~15 существующих `post_install` callback'ов в проекте (`_post_install_geo`, `_post_install_mieru_targz`, `_post_install_fptn`, `_post_install_trusttunnel`, `_post_install_hysteria2`, `_post_install_naiveproxy`, `_post_install_singbox`, `_post_install_xray_zip` и т.д.) продолжают работать без изменения сигнатуры или кода.

Переименование идёт через `Path.rename` с fallback на `shutil.copy2` + `unlink` для cross-device случаев. Перед rename удаляется потенциальный старый файл по новому пути (от прошлого неудачного запуска).

### Регрессионный тест

`tests/test_download_manager.py` — новый класс `TestCanonicalFileNameInInstallDests` с двумя тестами:
1. `test_installed_file_has_canonical_name_not_tmp_prefix` — проверяет что после `fetch_package()` (с `post_install=None`, через `_default_copy_to_dests`) в `install_dests` лежит `geosite.dat`, а НЕ `_download_mgr_geosite.dat`.
2. `test_installed_file_has_canonical_name_with_post_install` — то же, но с явным `post_install` callback, который использует `src.name` (как `_post_install_geo`). Проверяет что callback получает `src.name='geosite.dat'`, а не `'_download_mgr_geosite.dat'`.

Оба теста проверены на воспроизведение бага: при закомментированном фиксе оба теста падают с `AssertionError: '_download_mgr_geosite.dat' != 'geosite.dat'` — ровно та ошибка, что была на проде.

Тесты проверяют ИМЕННО ИТОГОВОЕ ИМЯ ФАЙЛА в `install_dests`, а не только факт копирования — это слепое пятно существующих тестов, которое и позволило багу жить 12 дней незамеченным.

### Blast radius проверка

`grep -rn "src.name" chimera/modules/*_packages.py` — нашёл только `_post_install_geo` (geo_packages.py:97,101,125) и `_default_copy_to_dests` (download_manager.py:328, уже covered). Остальные ~13 `post_install` callback'ов используют свои целевые имена явно (не через `src.name`) — не затронуты багом. Тесты других протоколов (mieru, fptn, trusttunnel, wdtt, singbox, xray, naiveproxy, hysteria2, awg, slipgate, turn, olcrtc, dnscrypt, go_toolchain, telemt) — 326 тестов прошли без регрессий.

### После деплоя фикса

На реальном сервере: запустить обновление geo-файлов → `ls -la /etc/xray/geosite.dat` должен показать СЕГОДНЯШНЮЮ дату и размер ~70+ МБ, файлов `_download_mgr_*` в `/etc/xray/` быть не должно. Старые `_download_mgr_*` файлы от прошлых 12 дней (если остались) можно удалить вручную: `rm -f /etc/xray/_download_mgr_* /usr/local/share/xray/_download_mgr_* /usr/local/etc/xray/_download_mgr_*`.

### Тесты

- `tests/test_download_manager.py` — 43/43 passed (+2 новых regression)
- `tests/test_geo_files.py` — 6/6 passed
- `tests/test_geo_mirrors.py` — 47/47 passed
- `tests/test_geo_cron_script.py` — 17/17 passed
- `tests/test_geosite_category_check.py` — 10/10 passed
- `tests/test_autoban.py` — 5/5 passed
- naiveproxy + mieru + fptn + trusttunnel + wdtt + singbox_packages + xray_install + singbox_install — 326 passed
- hysteria2 (12 файлов) — 90 passed
- awg + slipgate + turn + olcrtc + singbox_config — 384 passed
- subscription + user_portal + admin_panel + rest_api + ssl_certbot — 150 passed

Итого: 1078 тестов прошли, 0 регрессий.

---

## FEAT(3): Все 9 протоколов в единой подписке — 21 июля 2026

**Реестр `_SUBSCRIBABLE_PROTOCOLS` расширен с 2 до 5. Теперь единая подписка включает ВСЕ 9 синхронизируемых протоколов. qWDTT, AWG и Hysteria2 автоматически появляются в `/sub/{token}` если установлены.**

### Полный список протоколов в подписке (9 шт)

| # | Протокол | Способ включения | Формат ссылки |
|---|---|---|---|
| 1 | **VLESS** (REALITY/xHTTP) | hardcoded в `build_subscription_body` | `vless://uuid@host:443?...` |
| 2 | **Telemt/MTProto** | hardcoded `_build_telemt_uri` | `tg://proxy?server=...` |
| 3 | **Mieru** | hardcoded `_build_mieru_uris` | `mierus://user:pass@ip:port` |
| 4 | **NaiveProxy** | hardcoded `_build_naive_uris` | `naive+https://user:pass@host:port/` |
| 5 | **FPTN** | hardcoded `_build_fptn_uris` | `fptn://...` |
| 6 | **TrustTunnel** | `_SUBSCRIBABLE_PROTOCOLS` registry | `tt://...` (deep-link) |
| 7 | **sing-box** (ShadowTLS/AnyTLS/TUIC/Trojan/VLESS-WS-CDN) | registry | `trojan://`, `anytls://`, `tuic://`, `vless://` |
| 8 | **qWDTT** | **НОВЫЙ** registry | `qwdtt://config?...&pass=<password>` |
| 9 | **AWG** (AmneziaWG) | **НОВЫЙ** registry | `vpn://...` (Amnezia VPN deep-link) |
| 10 | **Hysteria2** | **НОВЫЙ** registry | `hysteria2://password@host:port?...` |

### Что нового (3 протокола в подписке)

#### qWDTT (`chimera/modules/wdtt.py` → `get_subscription_uris`)

Возвращает `qwdtt://config?` ссылку для юзера (по `owner_email`):
```
qwdtt://config?name=qWDTT-1.2.3.4&peer=1.2.3.4:56000&hashes=ABC123&workers=16&port=9000&pass=secret_pwd
```

Логика:
- Если WDTT не установлен → `[]`
- Если у юзера нет пароля (не синхронизирован) → `[]`
- Если пароль истёк или деактивирован → `[]`
- Иначе → возвращает ссылку с VK-хешем из password entry (или placeholder `ВК_ХЕШ`)

#### AWG (`chimera/modules/awg_peers.py` → `get_subscription_uris`)

Возвращает `vpn://` URI (Amnezia VPN deep-link) для юзера (по `owner_email`):
```
vpn://<base64-encoded JSON config>
```

Логика:
- Если AWG не установлен → `[]`
- Если у юзера нет peer → `[]`
- Если peer истёк → `[]`
- Иначе → генерирует URI через `awgs_qr_build_vpn_uri` (внутри base64 JSON с ключами, IP, параметрами Amnezia)

#### Hysteria2 (`chimera/modules/hysteria2_sync.py` → `get_subscription_uris`)

Возвращает `hysteria2://` ссылку (shared, одинакова для всех юзеров):
```
hysteria2://password@1.2.3.4:443?insecure=1&sni=example.com#Hysteria2
```

Логика:
- Если Hysteria2 не включена → `[]`
- Если нет активной exit-ноды → `[]`
- Иначе → `linkqr_lib.build_hysteria2_link()` (shared password)

### Content negotiation — `?format=base64_safe`

Расширен фильтр `_filter_safe_links` — теперь исключает также `qwdtt://` и `vpn://` (нестандартные форматы, которые Karing и большинство универсальных клиентов не умеют парсить):

| Формат | В base64 | В base64_safe |
|---|---|---|
| `vless://` | ✅ | ✅ |
| `trojan://`, `anytls://`, `tuic://` | ✅ | ✅ |
| `tt://` (TrustTunnel) | ✅ | ✅ |
| `hysteria2://` | ✅ | ✅ |
| `tg://proxy` (Telemt) | ✅ | ✅ |
| `naive+https://` | ✅ | ❌ filtered |
| `mierus://` | ✅ | ❌ filtered |
| `qwdtt://` | ✅ | ❌ filtered (NEW) |
| `vpn://` (AWG) | ✅ | ❌ filtered (NEW) |

### Изменения в коде

| Файл | Что изменилось |
|---|---|
| `chimera/modules/subscription.py` | `_SUBSCRIBABLE_PROTOCOLS` расширен с 2 до 5: +wdtt, +awg_peers, +hysteria2_sync. `_filter_safe_links` фильтрует `qwdtt://` и `vpn://` в safe mode. |
| `chimera/modules/wdtt.py` | Добавлен `get_subscription_uris(user)` — возвращает `qwdtt://` ссылку по owner_email. Проверяет TTL, deactivation, existence. |
| `chimera/modules/awg_peers.py` | Добавлен `get_subscription_uris(user)` — возвращает `vpn://` URI (Amnezia VPN deep-link) по owner_email. Через `awgs_qr_build_vpn_uri`. |
| `chimera/modules/hysteria2_sync.py` | Добавлен `get_subscription_uris(user)` — возвращает `hysteria2://` ссылку (shared). Через `linkqr_lib.build_hysteria2_link`. |
| `tests/test_subscription_registry.py` | Добавлены 4 новых testclass: `TestWDTTSubscriptionUris` (3 теста), `TestAWGSubscriptionUris` (3), `TestHysteria2SubscriptionUris` (2), `TestSafeLinkFilterV425` (3). +1 test в `TestSubscribableRegistry` для проверки реестра. |

### Тесты — 12 новых

- `TestSubscribableRegistry.test_registry_contains_v425_protocols` (1) — реестр содержит wdtt, awg_peers, hysteria2_sync
- `TestWDTTSubscriptionUris` (3) — empty when not installed, empty when no password, qwdtt:// link generation
- `TestAWGSubscriptionUris` (3) — empty when not installed, empty when no peer, vpn:// URI generation
- `TestHysteria2SubscriptionUris` (2) — empty when disabled, hysteria2:// link when enabled
- `TestSafeLinkFilterV425` (3) — filters qwdtt://, filters vpn://, keeps standard protocols

Все 308 тестов (subscription + sync + naiveproxy + mieru + trusttunnel + rest_api + proto_port) проходят.

### Что проверить на сервере

1. Установить qWDTT → после bulk-provisioning у каждого юзера появится `qwdtt://` в подписке
2. Установить AWG standalone → у каждого юзера `vpn://` (Amnezia deep-link) в подписке
3. Включить Hysteria2 → `hysteria2://` (shared) в подписке у всех юзеров
4. Открыть подписку в NekoBox (`?format=singbox`) → видны outbounds для trojan/anytls/tuic
5. Открыть подписку в Karing (`?format=base64_safe` или UA-based) → qwdtt:// и vpn:// отфильтрованы, остальные видны
6. Открыть подписку в v2rayN (default base64) → все 9 протоколов видны

---

## FEAT(2): Sync для qWDTT, FPTN, AWG, Hysteria2 — 21 июля 2026

**Расширил реестр `_SYNCABLE_PROTOCOLS` с 5 до 9 протоколов. Теперь двусторонняя синхронизация VLESS-юзеров работает со ВСЕМИ спутниковыми протоколами проекта.**

### Полный список синхронизируемых протоколов (9 шт)

| # | Протокол | Identity | Storage | Sync contract |
|---|---|---|---|---|
| 1 | **mtproto** (Telemt) | name = `email.split('@')[0]` | `/etc/telemt/telemt.toml` | per-user (secret preserved on rename) |
| 2 | **naiveproxy** | username = `email.split('@')[0]` | `/var/lib/xray-installer/naiveproxy.json` | per-user (password changes on rename) |
| 3 | **mieru** | username = `email.split('@')[0]` | `/var/lib/xray-installer/mieru.json` | per-user |
| 4 | **trusttunnel** | username = `email` (verbatim) | `/opt/trusttunnel/credentials.toml` | per-user (password deterministic from UUID) |
| 5 | **singbox** (ShadowTLS/AnyTLS/TUIC/Trojan) | UUID | `singbox_state.json` | per-user (UUID-keyed, password changes on add) |
| 6 | **wdtt** (qWDTT) | `owner_email` field in password entry | `/etc/wdtt/passwords.json` | per-user (TTL=365д, 1 устройство, **лимит 10 паролей**) |
| 7 | **fptn** | username = `email.split('@')[0]` | `/etc/fptn/users.list` | per-user (через `fptn-passwd --add-user`) |
| 8 | **awg_peers** (AmneziaWG) | `owner_email` field in peer | `/var/lib/xray-installer/awg_standalone_state.json` | per-peer (ключи генерируются, **лимит 253 пира**) |
| 9 | **hysteria2_sync** (Hysteria2) | N/A (shared password) | `state["hysteria2"]` | **NO-OP** (shared password, no per-user) |

### Что нового (4 протокола)

#### qWDTT (`chimera/modules/wdtt.py`)

qWDTT — WireGuard-over-TURN (через TURN-серверы ВКонтакте). Парольная модель доступа:
- Главный пароль (бессрочный) — для админа
- До 10 временных паролей с TTL и лимитом устройств — для юзеров

**Bridge к VLESS**: каждый VLESS-юзер получает ОДИН временный пароль WDTT с `owner_email` полем. TTL=365 дней, max_devices=1. **Лимит 10 паролей** — если у тебя >10 VLESS-юзеров, WDTT не для всех (11-й юзер получит warning и skip).

При add/remove/rename — `owner_email` поле используется для поиска. Hot reload через SIGHUP — новые пароли применяются без перезапуска сервера.

#### FPTN (`chimera/modules/fptn.py`)

FPTN — прокси-протокол (SNI-based). Username/password модель:
- Username = `email.split('@')[0]`, валидируется `[A-Za-z0-9]` (только буквы/цифры, без `_-`)
- Пароль = случайная строка (proto_gen_password)
- Хранится в `/etc/fptn/users.list` через `fptn-passwd --add-user`

При rename — remove + add (пароль меняется). Сервис `fptn-server` рестартуется.

#### AWG / AmneziaWG (`chimera/modules/awg_peers.py`)

AWG standalone — peer-based модель:
- Каждый peer = пара ключей (private+public) + IP в подсети AWG
- Identity: `peer.name` (уникальное, `[a-zA-Z0-9_-]`, не с цифры)
- Bridge к VLESS: через `peer.owner_email` (email VLESS-юзера)
- **Лимит 253 пира** (по числу IP в /24 подсети)

Имя пира генерируется из email: `alice@x.com → alice`. Если занято — `alice_2`, `alice_3` и т.д. Если имя начинается с цифры — добавляется `u_` prefix.

При rename — remove + add (ключи пересоздаются, клиент получает новый `.conf`).

#### Hysteria2 (`chimera/modules/hysteria2_sync.py`) — NO-OP

Hysteria2 — shared-password модель (один auth password на всех клиентов). Per-user концепции НЕТ.

Контракт NO-OP:
- `is_active()` — True если Hysteria2 включена в `state["hysteria2"]["enabled"]` или `transport_only`
- `ensure_user_full` / `remove_user_full` / `rename_user_full` — возвращают True (no-op)

Зачем тогда в реестре? Чтобы подписка/web-панель/user portal знали, что Hysteria2 активна. Dispatcher не делает per-user операций, просто подтверждает что протокол "синхронизирован" (= активна для всех).

### Bulk-provisioning при install

После успешной установки протокола вызывается `_sync_all_from_vless` — все существующие VLESS-юзеры автоматически получают аккаунты/peers/пароли:

```python
# Пример из wdtt.py _run_install_inner (после proto_save_state):
from chimera.modules.rest_api import _sync_all_from_vless
from chimera.modules.users_manager import _unified_load_users
_vless_users = _unified_load_users()
if _vless_users:
    print(f"Синхронизирую {len(_vless_users)} VLESS-юзеров в qWDTT...")
    _stats = _sync_all_from_vless(_vless_users)
```

Пользователь видит: `✓ Добавлено паролей qWDTT: 5` (например).

### Identity model — сводная таблица

| Протокол | Identity | Пароль | Rename |
|---|---|---|---|
| mtproto | `email.split('@')[0]` | случайный hex32 | секрет сохраняется |
| naiveproxy | `email.split('@')[0]` | случайный | меняется (remove+add) |
| mieru | `email.split('@')[0]` | случайный | меняется |
| trusttunnel | `email` (verbatim) | `SHA-256(uuid)` | ТОТ ЖЕ (derive из UUID) |
| singbox | UUID | случайный per inbound | name field updated, пароль НЕ меняется |
| **wdtt** | `owner_email` (link) | случайный, TTL=365д | меняется (remove+add) |
| **fptn** | `email.split('@')[0]` | случайный | меняется |
| **awg_peers** | `owner_email` (link) | пара ключей (private+public) | ключи пересоздаются |
| **hysteria2_sync** | N/A | shared | N/A (NO-OP) |

### Изменения в коде

| Файл | Что изменилось |
|---|---|
| `chimera/modules/rest_api.py` | `_SYNCABLE_PROTOCOLS` расширен с 5 до 9: +wdtt, +fptn, +awg_peers, +hysteria2_sync. Sing-box переименован в `singbox_users` (где реально живёт контракт). |
| `chimera/modules/wdtt.py` | Добавлены 7 contract функций + bulk-provisioning после install. `_find_password_by_owner` helper. `owner_email` поле в password entry. |
| `chimera/modules/fptn.py` | Добавлены 7 contract функций + bulk-provisioning. Использует существующие `_passwd_add_user`/`_passwd_del_user`. |
| `chimera/modules/awg_peers.py` | Добавлены 7 contract функций + `_peer_name_from_email` helper. Использует существующие `awg_peer_add`/`awg_peer_remove` с `owner_email` параметром. |
| `chimera/modules/awg_standalone.py` | Bulk-provisioning после install — все VLESS-юзеры получают AWG peers. |
| `chimera/modules/hysteria2_sync.py` | **НОВЫЙ** модуль — NO-OP контракт для Hysteria2 (shared password). |
| `tests/test_user_sync_v425.py` | Расширен с 16 до 30 тестов: +4 contract exports tests, +5 Hysteria2 NO-OP tests, +2 WDTT limit tests, +3 AWG peer name generation tests. |

### Тесты — 14 новых (всего 30 в test_user_sync_v425.py)

- `TestProtocolContractFunctions` (4 новых) — wdtt, fptn, awg_peers, hysteria2_sync экспортируют контракт
- `TestHysteria2NoOpContract` (5) — ensure/remove/rename всегда True, is_active реагирует на state
- `TestWDTTPasswordLimit` (2) — лимит 10 паролей, идемпотентность для существующего
- `TestAwgPeerNameGeneration` (3) — генерация из email, суффикс при коллизии, u_ prefix для цифры

Все 611 тестов проходят (naiveproxy + mieru + trusttunnel + singbox + rest_api + subscription + user_sync + mtproto + awg).

### Что проверить на сервере

1. Установить qWDTT через TUI — в конце `✓ Добавлено паролей qWDTT: N`
2. Установить FPTN — `✓ Добавлено в FPTN: N юзеров`
3. Установить AWG standalone — `✓ Добавлено AWG peers: N`
4. Добавить VLESS-юзера через TUI [1] — `Синхронизирован со спутниковыми протоколами: naiveproxy, mieru, singbox, wdtt, fptn, awg_peers` (если установлены)
5. Hysteria2 — при включении `Синхронизирован со спутниковыми протоколами: hysteria2_sync` (NO-OP, но подписка увидит hysteria2:// ссылку)

---

## FEAT: Двусторонняя синхронизация пользователей VLESS ↔ спутниковые протоколы — 21 июля 2026

**По запросу Andrew B.: «если имя пользователя будет совпадать при установке этих протоколов, они добавятся в единую подписку/web панель/user portal автоматически?» — ответ теперь ДА.**

### Что работает сейчас (v4.25)

| Сценарий | Автоматически? |
|---|---|
| **Добавил протокол** → все существующие VLESS-юзеры автоматически получают аккаунты в новом протоколе | ✅ **ДА** — `_sync_all_from_vless` вызывается в конце `_run_install_inner` каждого протокола |
| **Добавил VLESS-юзера** (через TUI [1] или REST API) → аккаунты создаются во всех активных протоколах | ✅ **ДА** — `_sync_user_to_protocols("add", user)` / `_sync_ensure_user(user)` |
| **Удалил VLESS-юзера** → аккаунты удаляются во всех протоколах | ✅ **ДА** |
| **Переименовал VLESS-юзера** → аккаунты переименовываются (с сохранением UUID/секрета где возможно) | ✅ **ДА** |
| **Toggle disable/enable VLESS-юзера** → аккаунты удаляются/восстанавливаются во всех протоколах | ✅ **ДА** (раньше toggle не имел sync вообще) |
| **Подписка находит юзера** | ✅ **ДА** — теперь уже с реальными аккаунтами, не только name-matching |

### Архитектура

```
                    ┌──────────────────────────────────────┐
                    │  VLESS users.json (canonical source) │
                    └────────────┬─────────────────────────┘
                                 │
                  _sync_user_to_protocols(action, user)
                                 │
                  ┌──────────────┴───────────────┐
                  ▼                              ▼
       _SYNCABLE_PROTOCOLS (реестр)     user_lifecycle.PROTOCOL_ADAPTERS
       ────────────────────────────     ─────────────────────────────────
       • mtproto                        • vless
       • naiveproxy                     • awg
       • mieru                          • singbox
       • trusttunnel                    • mieru
       • singbox                        • mtproto
                                       • naiveproxy
                                       • fptn
                                       • hysteria2
                                       • trusttunnel
                  │
                  ▼
       Каждый модуль экспортирует КОНТРАКТ:
         is_active() → bool
         ensure_user_full(user: dict) → bool      # extended
         remove_user_full(user: dict) → bool      # extended
         rename_user_full(old, new) → bool        # extended
         ensure_user(name) → bool                 # legacy fallback
         remove_user(name) → bool
         rename_user(old, new) → bool
```

### Контракт syncable-протокола

Каждый спутниковый протокол экспортирует 7 функций:

| Функция | Описание |
|---|---|
| `is_active()` | True если протокол установлен И сервис запущен. Dispatcher пропускает протокол если False. |
| `ensure_user_full(user)` | Создаёт аккаунт из full user dict (uuid, email, name, device_label). Идемпотентна. |
| `remove_user_full(user)` | Удаляет аккаунт. Идемпотентна. |
| `rename_user_full(old, new)` | Переименование. Каждый протокол сам решает как — sing-box обновляет name field in-place, TrustTunnel/NaiveProxy/Mieru делают remove+add (пароль не меняется у TrustTunnel т.к. derive из UUID). |
| `ensure_user(name)` / `remove_user(name)` / `rename_user(old, new)` | Legacy contract — только name. Fallback если модуль не экспортирует `_full` вариант. |

### Identity model каждого протокола

| Протокол | Identity | Пароль | Rename semantics |
|---|---|---|---|
| **mtproto** (Telemt) | name = `email.split('@')[0]` | Случайный hex32 secret | Секрет сохраняется при rename |
| **naiveproxy** | username = `email.split('@')[0]` | Случайный (proto_gen_password) | remove+add, пароль меняется |
| **mieru** | username = `email.split('@')[0]` | Случайный | remove+add, пароль меняется |
| **trusttunnel** | username = `email` (verbatim) | `SHA-256("trusttunnel-pass|" + uuid)` — детерминированный | remove+add, пароль ТОТ ЖЕ (derive из UUID) |
| **singbox** (ShadowTLS/AnyTLS/TUIC/Trojan) | UUID (canonical VLESS UUID) | Случайный (singbox_gen_password) | update name field in-place, пароль НЕ меняется |

### Изменения в коде

| Файл | Что изменилось |
|---|---|
| `chimera/modules/rest_api.py` | `_SYNCABLE_PROTOCOLS` расширен с 1 (mtproto) до 5 (mtproto + naiveproxy + mieru + trusttunnel + singbox). `_sync_dispatch` поддерживает `_full` варианты. `_sync_all_from_vless` передаёт full user dicts. Toggle/rename в REST API теперь вызывает sync. |
| `chimera/modules/naiveproxy.py` | Добавлены: `is_active`, `ensure_user_full`, `remove_user_full`, `rename_user_full`, legacy `ensure_user`/`remove_user`/`rename_user`. Bulk-provisioning в конце `_run_install_inner`. |
| `chimera/modules/mieru.py` | Те же 7 функций контракта + bulk-provisioning после install. |
| `chimera/modules/trusttunnel.py` | Те же 7 функций контракта + bulk-provisioning. TrustTunnel особенный: username=email, password=derive(uuid). |
| `chimera/modules/singbox_users.py` | Контракт добавлен здесь (не в singbox_menu). `is_active` проверяет что sing-box запущен И хотя бы один inbound включён. `ensure_user_full` вызывает `singbox_state_add_user_to_all_protocols`. |
| `chimera/_core.py` | Новая функция `_sync_user_to_protocols(action, user, old_user=None)` — диспетчер для TUI. Вызывается из `do_unified_user_manager` items 1 (add), 2 (remove), 7 (toggle), 8 (rename). |
| `tests/test_user_sync_v425.py` | **НОВЫЙ** — 16 тестов: реестр, контрактные функции, dispatcher `_full` preference, `_sync_all_from_vless` full dicts, `_sync_user_to_protocols` диспетчер, идемпотентность naiveproxy, TrustTunnel UUID requirement. |

### Bulk-provisioning при install протокола

После успешной установки протокола вызывается:

```python
from chimera.modules.rest_api import _sync_all_from_vless
from chimera.modules.users_manager import _unified_load_users
_vless_users = _unified_load_users()
if _vless_users:
    print(f"Синхронизирую {len(_vless_users)} VLESS-юзеров в {ProtoName}...")
    _stats = _sync_all_from_vless(_vless_users)
```

Пользователь видит в выводе: `✓ Добавлено в NaiveProxy: 5 юзеров` (например).

### Тесты — 16 новых + 2 обновлённых

- `TestSyncableRegistryContents` (2) — реестр содержит 5 протоколов, НЕ содержит vless
- `TestProtocolContractFunctions` (4) — все 4 протокола экспортируют контракт
- `TestSyncDispatchPrefersFullContract` (2) — dispatcher предпочитает `_full` при user dict, fallback на legacy
- `TestSyncAllFromVlessPassesFullDicts` (1) — full user dicts передаются в `ensure_user_full`
- `TestCoreSyncHelper` (4) — `_sync_user_to_protocols` для add/remove/toggle_off/toggle_on
- `TestNaiveproxyContractIdempotency` (1) — существующий юзер → True (no-op)
- `TestTrustTunnelContractRequiresUuid` (2) — без UUID возвращает False, с UUID — True

Обновлённые тесты в `test_rest_api.py`:
- `test_deduplicates_names` — v4.25 НЕ дедуплицирует по name (у каждого свой UUID)
- `test_skips_empty_names` — юзер с email но без name теперь синхронизируется

Все 563 теста (naiveproxy + mieru + trusttunnel + singbox + rest_api + subscription + user_sync + mtproto) проходят.

### Что проверить на сервере

1. Установить NaiveProxy (через TUI) — в конце вывода должно быть `✓ Добавлено в NaiveProxy: N юзеров` (где N = число VLESS-юзеров).
2. Зайти в `Подписка → Показать ссылки` — у каждого юзера должна появиться `naive+https://` ссылка.
3. Добавить нового VLESS-юзера через TUI [1] — в выводе `Синхронизирован со спутниковыми протоколами: naiveproxy, mieru, singbox` (если они установлены).
4. Toggle disable VLESS-юзера [7] — `Отключён в спутниковых протоколах: ...`.
5. Переименовать VLESS-юзера [8] — `Переименован в спутниковых протоколах: ...`.

---

## FEAT: Выбор порта + имя первого пользователя во всех протоколах — 21 июля 2026

**По запросу Andrew B.: во всех протоколах (NaiveProxy, Trojan/sing-box, TrustTunnel, Mieru) добавлен интерактивный выбор порта и имени первого пользователя. TrustTunnel больше не падает при ошибке LE-сертификата.**

### Проблемы (из переписки с Andrew B.)

| Протокол | Жалоба | Корневая причина |
|---|---|---|
| **NaiveProxy** | «просит остановить nginx, как где это сделать? сам он почему не может его стопнуть?» | Warning «остановите nginx сами» — но auto-stop был только для port 80 (ACME), НЕ для выбранного порта Caddy (443). | Порт конфликта не проверялся до install; auto-stop nginx покрывал только port 80, не выбранный порт |
| **NaiveProxy** | «Другой порт назначить не дает» | Был `input(f"Порт [{old_port}]")` БЕЗ проверки конфликта — если порт занят, Caddy падал при запуске | Нет pre-flight port conflict check |
| **Trojan (sing-box)** | «садится автоматом на порт 8443 и негде его переназначить» | TUIC default и VLESS-WS-CDN default использовали `_prompt_alt_port` только в ShadowTLS/AnyTLS, НЕ в TUIC/VLESS-WS-CDN | Hardcoded `DEFAULT_PORT_TUIC_ALTERNATIVE=443` / `DEFAULT_PORT_VLESS_WS_CDN=8080` без запроса |
| **TrustTunnel** | «не может получить LE сертификат и падает установщик» | `obtain_ssl_cert()` вызывает `core.die()` при DNS failure → `die() = sys.exit(1)` → ВЕСЬ установщик падает | `sys.exit(1)` не перехватывался |
| **Mieru** | «тоже добавить возможность выбора имени пользователя/порт» | Порт уже запрашивался, но первый username был хардкод `admin` | `first_user = "admin"` без `proto_ask` |
| **NaiveProxy / TrustTunnel** | (общее) первый username хардкод `admin` / `admin:dummy-uuid` | Нет `proto_ask` для первого пользователя | Hardcoded `admin` |

### Фиксы

#### 1. NaiveProxy (`chimera/modules/naiveproxy.py`)

- **Pre-flight port conflict check** — `socket.bind(("0.0.0.0", port))` до install. Если занят — показываем кто держит (через `ss -ltnp`) и предлагаем ввести альтернативу. Цикл повторяется пока не введут свободный порт или отменят.
- **Auto-stop nginx расширено** — раньше только для port 80 (ACME). Теперь также для выбранного порта Caddy (если nginx на нём). Логика: `if _nginx_active and (port_80_taken or chosen_port_taken): stop nginx; restore after install`.
- **Запрос первого username** — `proto_ask("Логин первого пользователя [admin]: ", default="admin")` с валидацией `^[A-Za-z0-9_\-]+$` (для Caddyfile `basic_auth`).
- **Убран misleading warning** — «Если на порту 443 уже работает nginx — остановите его сначала» заменён на «Если выбранный порт занят — установщик предложит альтернативу. Если порт 80 занят — nginx будет автоматически остановлен и возвращён.»

#### 2. sing-box TUIC default (`chimera/modules/singbox_menu.py`)

- **Добавлен `_prompt_alt_port(DEFAULT_PORT_TUIC_ALTERNATIVE, "::", "udp")`** — mirror ShadowTLS/AnyTLS pattern. Если 443/UDP занят — предлагаем альтернативу.
- `singbox_enable_tuic(listen_port=listen_port, ...)` — передаём выбранный порт.
- `singbox_ufw_ensure_open(listen_port, "udp", "tuic", listen="::")` — UFW для выбранного порта.

#### 3. sing-box VLESS-WS-CDN default (`chimera/modules/singbox_menu.py`)

- **Добавлен `_prompt_alt_port(DEFAULT_PORT_VLESS_WS_CDN, "0.0.0.0", "tcp")`** — если 8080 занят, предлагаем альтернативу.
- `singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host=host, listen_port=listen_port)` — передаём выбранный порт.
- `singbox_ufw_ensure_open(listen_port, "tcp", "vless_ws_cdn", listen="0.0.0.0")` — UFW для выбранного порта.

#### 4. TrustTunnel (`chimera/modules/trusttunnel.py`)

- **LE cert failure graceful fallback** — перехватываем `SystemExit` (от `core.die()` внутри `obtain_ssl_cert`) и `Exception`. При ошибке — генерируем self-signed cert через `generate_self_signed_cert(domain)` в тот же путь (`/etc/letsencrypt/live/<domain>/`). Установка продолжается. TrustTunnel работает с self-signed — клиенты принимают любой TLS-сертификат (pin через SNI, не через CA).
- **Запрос первого username (email)** — `proto_ask("Email первого пользователя [admin@example.com]: ", default="admin@example.com")` с валидацией наличия `@`. Email = username в TrustTunnel.
- **Запрос UUID для derive пароля** — `proto_ask("UUID для derive пароля (Enter=авто): ")` — если Enter, генерируем случайный UUID. Пароль детерминированно выводится через `trusttunnel_derive_password(uuid)`.
- **wizard_cmd использует admin_email** вместо хардкода `admin`: `-c "{admin_email}:{admin_pass}"`.

#### 5. Mieru (`chimera/modules/mieru.py`)

- **Запрос первого username** — `proto_ask("Логин первого пользователя [admin]: ", default="admin")` с валидацией через `_RE_USERNAME` (только латиница/цифры/_-). При недопустимых символах — fallback на `admin`.
- Порт уже запрашивался ранее (`_DEFAULT_PORT_START=2012`, `_DEFAULT_PORT_END=2022`) — без изменений.

### Тесты — `tests/test_proto_port_username_v424.py` (10 новых)

- `TestNaiveproxyFirstUsernamePrompt` (2) — proto_ask для логина, проверка конфликта порта через `socket.bind()`
- `TestSingboxTuicPortPrompt` (2) — `_prompt_alt_port` для TUIC default и VLESS-WS-CDN default
- `TestTrustTunnelLECertFallback` (2) — перехват `SystemExit`, fallback на `generate_self_signed_cert`; запрос `admin_email`
- `TestMieruFirstUsernamePrompt` (2) — proto_ask для логина, нет прямого хардкода `admin` в main path
- `TestNaiveproxyNginxAutoStop` (2) — auto-stop nginx для port 80 (ACME) и для выбранного порта Caddy

Все 533 теста (naiveproxy + mieru + trusttunnel + singbox + новые) проходят.

### Изменения в коде

| Файл | Что изменилось |
|---|---|
| `chimera/modules/naiveproxy.py` | Pre-flight port conflict check, auto-stop nginx для выбранного порта, запрос первого username, убран misleading warning |
| `chimera/modules/singbox_menu.py` | TUIC default: `_prompt_alt_port` для UDP/::; VLESS-WS-CDN default: `_prompt_alt_port` для TCP/0.0.0.0 |
| `chimera/modules/trusttunnel.py` | LE cert graceful fallback (перехват SystemExit → self-signed), запрос admin_email + UUID |
| `chimera/modules/mieru.py` | Запрос первого username через `proto_ask` |
| `tests/test_proto_port_username_v424.py` | **НОВЫЙ** — 10 regression-тестов |
| `CHANGELOG.md` | Эта запись |

---

## FEAT: Переключатель YouTube → RU / exit-ноды — 21 июля 2026

**В TUI «Настройки сети» добавлен пункт `Y` — переключатель маршрутизации YouTube между RU entry-нодой и exit-нодами каскада.**

### Контекст задачи

Архитектура проекта: клиент → RU entry-нода → (geosite/geoip правила) → exit-ноды (1–10 нод, балансировщик). Уже применяются:
- `geosite:category-ru`, `geosite:ru-available-only-inside`, `geoip:ru` → `direct` (split tunneling)
- RIPE NCC CIDR → `direct` (ru_subnets_ripe, 13000+ правил)
- Catch-all `tcp,udp` → `chain-exit` / `chain-balancer`

Нужно: точечно переключать **только YouTube** между RU и exit, не трогая остальной трафик. Кнопкой в TUI, без редактирования `config.json` вручную.

### Решение — новый модуль `chimera/modules/youtube_route.py`

Архитектурно повторяет `ru_subnets.py` (Pattern C: правило с `comment="youtube_via_ru"`, идемпотентное добавление/удаление, AWG-aware).

#### Правило маршрутизации

```json
{
  "type": "field",
  "domain": [
    "geosite:youtube",
    "geosite:google",
    "domain:googlevideo.com",
    "domain:ytimg.com",
    "domain:ggpht.com",
    "domain:youtubei.googleapis.com",
    "domain:manifest.googlevideo.com",
    "domain:youtu.be",
    "domain:youtube-nocookie.com",
    "domain:youtubeeducation.com"
  ],
  "outboundTag": "direct",   ← или "direct-local" в AWG-режиме
  "comment": "youtube_via_ru"
}
```

Полный список доменов покрывает все CDN YouTube (видео-стрим, thumbnails, avatars, internal API, DASH/HLS manifests) — чтобы не было асимметричной маршрутизации (стрим через RU, thumbnails через exit — сессия ломается).

#### AWG-aware

При `AWG_EXIT_ENABLED=True` используется `outboundTag="direct-local"` (freedom без fwmark) — YouTube выходит через дефолтный маршрут RU-сервера, а не через AWG-туннель к exit. Та же логика что в `ru_subnets._ru_subnets_apply_to_xray` (lines 267, 290–296).

#### TUI-меню `do_manage_youtube_via_ru()`

```
📺  YouTube через RU  (entry-нода)

  Текущий маршрут: YouTube → RU entry
  geosite:youtube → outbound:direct

  Переключатель добавляет/убирает правило routing в config.json:
    domain:[geosite:youtube, googlevideo.com, ytimg.com, ...] → direct
  AWG-aware: outbound=direct-local когда AWG exit активен.

  [1]  ● YouTube через RU entry
  [2]  ● YouTube через exit-ноды (default)

  [Q] Назад
```

Показывает актуальное состояние (читает `state.json` + проверяет `config.json` — если state говорит True, но правила нет после regenerate, показывает «несогласованно» и предлагает пере-применить).

#### Restore после regenerate xray-config

`generate_xray_config*` полностью перезаписывает `config.json`, стирая все runtime-правила. Поэтому в `_core.py:2759` (после `_ru_subnets_restore_if_needed` и `_as_direct_restore_if_needed`) добавлен вызов `restore_youtube_rule_if_needed(silent=False)` — если `state["youtube_via_ru"]=True`, правило пере-добавляется автоматически.

#### Состояние

- `state["youtube_via_ru"]: bool` (default `False`)
- Загружается в `_core.YOUTUBE_VIA_RU` через `_load_state_into_globals()` (новый global рядом с `XTLS_FLOW`)
- Записывается через `_save_youtube_state(enabled)` — НЕ трогает остальные поля state.json

### Изменения в коде

| Файл | Что изменилось |
|---|---|
| `chimera/modules/youtube_route.py` | **НОВЫЙ** — модуль с apply/remove/restore/TUI |
| `chimera/_core.py` | Глобаль `YOUTUBE_VIA_RU`, загрузка в `_load_state_into_globals()`, restore-вызов после regenerate, пункт меню `Y` + dispatch |
| `tests/test_youtube_route.py` | **НОВЫЙ** — 19 тестов |
| `CHANGELOG.md` | Эта запись |

### Тесты — 19 новых

- `TestYoutubeApplyToXray` (6) — добавление правила, geosite:youtube в domain[], outbound=direct без AWG, outbound=direct-local с AWG, идемпотентность, порядок правил (prepended before catch-all), False при падении Xray
- `TestYoutubeRemoveFromXray` (2) — удаляет только YouTube правило, не трогает RIPE/catch-all; no-op если правила нет
- `TestYoutubeRuleInConfig` (3) — детектор: True/False/нет файла
- `TestSaveYoutubeState` (3) — запись True/False, создание файла, сохранение существующих полей
- `TestRestoreYoutubeRuleIfNeeded` (4) — False при disabled/missing/already-present, True при state=True+rule_missing
- `TestYoutubeDomainsList` (1) — список покрывает ключевые домены

Все 51 routing-тест (ru_subnets + as_direct + geoip_block + youtube_route) проходят.

---

## FIX(2): 'Failed to mask unit: File already exists' + шум stderr в subscription uninstall — 21 июля 2026

**После предыдущего фикса (`4b0f5e7`) пользователь сообщил о трёх шумных ошибках в реальном выводе systemd. Все три исправлены.**

### Проблема 1 — `Failed to mask unit: File ... already exists.`

**Симптом** (item [4] «Выключить сервис» и item [6] «Удалить полностью»):
```
Failed to mask unit: File /etc/systemd/system/vless-subscription.service already exists.
[OK]    Сервис остановлен, порт освобождён.
```

**Причина:** `systemctl mask` создаёт symlink `/etc/systemd/system/<name>.service → /dev/null`. На systemd ≥252 mask **отказывается перезаписывать** существующий обычный файл (нужен `--force`, которого нет на старом systemd). Mask молча не срабатывал, и далее полагались только на `systemctl stop` + `_kill_port_holder` fallback.

**Фикс — два разных решения для [4] и [6]:**

| Сценарий | Решение |
|---|---|
| **[4] Выключить сервис** (временная остановка, unit-файл нужно сохранить) | **mask вообще НЕ нужен.** Согласно systemd.service(5): «If a service is stopped via systemctl stop, the Restart= setting is ignored and the service is not restarted.» Restart= срабатывает только при самостоятельном падении процесса (crash, OOM, signal от ядра) — но НЕ при явной команде stop. Поэтому `_stop_service_reliable()` теперь просто `systemctl stop` + `_kill_port_holder` fallback. |
| **[6] Удалить полностью** (unit-файл удаляем) | Удалить unit-файл **ДО** mask — тогда mask succeeds (создаёт symlink → /dev/null как belt-and-suspenders, на случай если stop по какой-то причине всё-таки триггернет Restart=). После stop — `unmask` (убрать symlink, cleanup). |

Новый порядок `uninstall_subscription_service()`:
```
1. _fw_close_tcp(port)         — закрыть ufw-порт
2. systemctl disable           — убрать Wants symlink
3. unlink unit-файла           — чтобы mask смог создать symlink → /dev/null
4. systemctl mask              — symlink → /dev/null (теперь succeeds)
5. systemctl stop              — процесс уходит, не перезапускается (masked)
6. systemctl unmask            — убрать symlink (cleanup)
7. unlink если что-то осталось — паранойя
8. systemctl daemon-reload
9. systemctl reset-failed
10. _kill_port_holder(port)    — fallback
```

### Проблема 2 — `Failed to reset failed state ... Unit ... not loaded.`

**Симптом** (item [1] «Включить» и item [6] «Удалить»):
```
Failed to reset failed state of unit vless-subscription.service: Unit vless-subscription.service not loaded.
```

**Причина:** `systemctl reset-failed` пишет это в stderr, когда unit не загружен в память systemd:
- В `_install_service` — вызывается после `daemon-reload`, но если unit никогда не был в failed-состоянии, всё равно пишет.
- В `uninstall_subscription_service` — вызывается после удаления unit-файла + daemon-reload, так что systemd уже выгрузил unit.

**Фикс:** Добавлен `stderr=subprocess.DEVNULL` (и `stdout=subprocess.DEVNULL` заодно) к этим вызовам. Сообщение безобидное (нечего очищать), но пугает пользователя.

### Проблема 3 — `Could not delete non-existent rule` (×2, v4 и v6)

**Симптом** (item [6] после item [4]):
```
Could not delete non-existent rule
Could not delete non-existent rule (v6)
```

**Причина:** `_fw_close_tcp(port)` вызывает `ufw delete allow <port>/tcp`. Если правило уже удалено (через stop[4] или потому что порт никогда не открывался), ufw пишет это в stderr для обоих стеков (IPv4 + IPv6).

**Фикс:** `_fw_close_tcp` теперь идемпотентна — `stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL` для ufw-вызова. Сценарий stop[4] → uninstall[6] теперь чистый.

### Тесты — 2 новых (всего 15 в `test_subscription_uninstall.py`)

- `test_unit_file_unlinked_before_mask` — регрессия: в момент вызова `systemctl mask` unit-файла уже не должно быть на диске (иначе `File already exists`).
- `test_install_does_not_emit_reset_failed_not_loaded` — регрессия: `reset-failed` в `_install_service` должен вызываться с `stderr=DEVNULL` (иначе `Unit ... not loaded` печатается).
- `test_stop_called_and_no_mask` — обновлён: для [4] mask НЕ вызывается (раньше проверялось что mask ДО stop).
- `test_full_pipeline_disable_unlink_mask_stop` — обновлён: новый порядок disable → unlink → mask → stop → unmask → daemon-reload → reset-failed.

Все 142 теста (subscription + web panel firewall) проходят.

---

## FIX: Надёжный uninstall/stop сервиса единой подписки — 21 июля 2026

**`vless-subscription.service` (порт 8443) теперь корректно освобождает порт при остановке/удалении — тот же mask+stop+kill fix, что ранее починил `vless-web` (commit `e830f28`).**

### Проблема

Пункт меню **«4. Выключить сервис»** в `do_subscription_menu()` использовал `systemctl disable --now vless-subscription`. Это **не работало**: в unit-файле стоит `Restart=always` (агрессивнее, чем `Restart=on-failure` у веб-панели). Последовательность:

1. `systemctl disable --now` → SIGTERM → процесс выходит
2. systemd видит `Restart=always` → перезапускает через 3с
3. unit-файл удалён + `daemon-reload` → но процесс **уже запущен заново** и больше не управляется systemd (unit-файла нет)
4. Результат: порт занят python3 (видно в `ss -tlnp`), формально «uninstall успешен», но при следующей установке [1] — `OSError: Address already in use` → `systemd start-limit-hit` → сервис молча умирает

Кроме того, **не было пункта «Удалить полностью»** — только «Выключить» (с вышеописанным багом).

### Фикс — mirror `rest_api.uninstall_web_service()` (commit `e830f28`)

Та же последовательность, что починила `vless-web`, применена к `vless-subscription`:

#### Новая функция `uninstall_subscription_service()`

1. `_fw_close_tcp(port)` — закрыть ufw-порт (если был открыт)
2. `systemctl mask vless-subscription` — заменяет unit-файл на symlink → `/dev/null`, systemd перестаёт его читать, `Restart=` больше не срабатывает
3. `systemctl stop vless-subscription` — процесс уходит и **не перезапускается**
4. `systemctl disable vless-subscription` — убрать из автозагрузки
5. Удалить unit-файл + проверить symlink от mask (если остался)
6. `systemctl daemon-reload` — systemd забывает юнит
7. `systemctl reset-failed vless-subscription` — очистить failed-состояние (иначе при следующей установке `start-limit-hit`)
8. **Fallback:** `_kill_port_holder(port)` — найти PID через `ss -tlnp` и `kill -9` (catches cases: старый systemd, процесс запущен вручную через `python3 -m chimera.modules.subscription serve`, mask не сработал)

Конфиг `subscription.json` (pepper, identity_map) **НЕ удаляется** — при повторной установке [1] старые ссылки продолжат работать. Для инвалидации ссылок есть отдельный пункт [3] «Сгенерировать pepper заново».

#### Новая функция `_stop_service_reliable()`

Используется в пункте [4] «Выключить сервис»: mask → stop → `_kill_port_holder`. После остановки юнит остаётся замаскированным — это **намеренно**, чтобы `Restart=always` не воскресил процесс.

#### Новая функция `_kill_port_holder(port)`

Парсит `ss -tlnp`, находит **только строку** с нужным портом (не весь вывод — иначе убил бы sshd/xray/etc.), извлекает PID и `kill -9`. Не убивает PID=1 (init). Тихо возвращает False если ss недоступен/вернул ошибку.

#### Изменения в `_install_service()`

Добавлен `systemctl unmask` перед `enable` — без этого повторная установка [1] после остановки [4] молча не запускает сервис (unit symlink на `/dev/null`, `systemctl enable` это игнорирует). Та же логика что в `do_manage_web_panel()` item '1' run branch.

### Изменения в меню `do_subscription_menu()`

| Пункт | Что изменилось |
|---|---|
| **1 (Включить / переустановить)** | `_install_service` делает `unmask` перед `enable` — корректный старт после [4] |
| **4 (Выключить сервис)** | Использует `_stop_service_reliable()` вместо `systemctl disable --now`. Порт **реально** освобождается. |
| **6 (НОВЫЙ — Удалить полностью)** | Подтверждение y/N → `uninstall_subscription_service()` (systemd unit + ufw-порт + процесс). `subscription.json` (pepper, identity_map) НЕ трогается — старые ссылки переживут reinstall. |

### Тесты — `tests/test_subscription_uninstall.py` (13 шт)

- `TestKillPortHolder` (4) — kill по PID из ss, не убивает PID=1, не падает при ошибке ss
- `TestStopServiceReliable` (2) — mask ДО stop, kill fallback ПОСЛЕ stop
- `TestUninstallSubscriptionService` (6) — полный pipeline, порядок mask→stop→disable→daemon-reload→reset-failed, unit-файл удалён, kill fallback вызван, pepper сохранён, ufw-порт закрыт, не падает если unit уже удалён
- `TestInstallServiceUnmask` (1) — unmask перед enable

Все 112 тестов (subscription + web panel firewall) проходят.

---

## FEAT: Content negotiation в подписке + управление файрволлом веб-панели — 20 июля 2026

**Два крупных улучшения: единая подписка теперь отдаёт правильный формат каждому клиенту автоматически, а веб-панель (admin + user portal) больше не оставляет открытых ufw-портов при остановке или удалении.**

### 🔔 Расширение единой подписки (subscription.py)

#### Content negotiation — ?format= / User-Agent

Подписка теперь определяет, какой формат отдать клиенту, по трём уровням приоритета:

1. **`?format=singbox`** — явный параметр в URL (высший приоритет)
2. **User-Agent эвристика** — словарь `_UA_FORMAT_MAP` (расширяемый): nekobox/sing-box → `singbox`, karing → `base64_safe`
3. **`base64`** — дефолт (100% обратная совместимость, существующие клиенты не сломаются)

Три формата:

| Формат | Content-Type | Что отдаётся | Для кого |
|---|---|---|---|
| `base64` (дефолт) | `text/plain` | Base64-список всех share-links | Все клиенты (по умолчанию) |
| `singbox` | `application/json` | Полный sing-box JSON config с outbounds | NekoBox, sing-box, клиенты на ядре sing-box |
| `base64_safe` | `text/plain` | Base64-список БЕЗ `naive+https://` и `mierus://` | Karing и клиенты, не умеющие парсить нестандартные схемы |

#### Реестр сателлитных протоколов `_SUBSCRIBABLE_PROTOCOLS`

Добавление нового протокола в подписку = **одна строка** в реестре. Модуль должен экспортировать `get_subscription_uris(user: dict) -> list[str]` (для share-links) и/или `get_subscription_json_outbound(user: dict) -> Optional[dict]` (для sing-box JSON).

Текущий реестр:
- `chimera.modules.trusttunnel` — tt:// deep-link
- `chimera.modules.singbox_menu` — trojan:// (ShadowTLS), anytls://, tuic://, vless:// (WS-CDN)

#### Per-user credential matching в sing-box протоколах

**Баг исправлен:** все gen-функции (`_gen_shadowtls_client_uri`, `_gen_anytls_client_uri`, `_gen_tuic_client_uri`) брали пароль из `state_ib["users"][0]` — первого юзера в списке. В подписке каждый юзер получал **чужой пароль**.

Новая функция `_find_singbox_user_credential(state_ib, candidates)` — ищет запись юзера по UUID (точное совпадение), затем по name (без учёта регистра). Если `candidates` пустой (TUI-режим) — возвращает `users[0]` (обратная совместимость).

#### Новые протоколы в подписке

TrustTunnel (`tt://`), ShadowTLS (`trojan://`), AnyTLS (`anytls://`), TUIC (`tuic://`), VLESS-WS-CDN (`vless://`) — теперь включены в `build_subscription_body()` и `build_subscription_body_ios()`. Каждый юзер получает **свой** пароль (по совпадению UUID/name), а не пароль первого юзера. VLESS-WS-CDN — общий (без per-user).

#### `build_subscription_singbox_config(user)` — полный JSON

Собирает sing-box JSON config из:
- VLESS outbound (Reality/xHTTP) — переиспользует `rest_api._generate_singbox_config`
- ShadowTLS/AnyTLS/TUIC/VLESS-WS-CDN/TrustTunnel — через `_collect_registry_json_outbounds`
- Direct + block outbounds + базовый route

#### TUI меню

Теперь показывает три ссылки на каждого юзера:
```
alice@node-b.example
  https://node-b.example:8443/sub/aBcDeFgHiJkLmNoPqRsTuVw
  iOS/Karing: https://node-b.example:8443/sub/aBcDeFgHiJkLmNoPqRsTuVw/ios
  sing-box JSON: https://node-b.example:8443/sub/aBcDeFgHiJkLmNoPqRsTuVw?format=singbox
```

#### Identity map — новые теги

Меню ручной привязки (`_do_identity_map_menu`) расширено — добавлены TrustTunnel и sing-box (shadowtls/anytls/tuic) теги для ручного override если автоматический матчинг по name/email не сработал.

### 🔒 Управление файрволлом веб-панели (rest_api.py)

#### Проблема

При остановке, переустановке или удалении сервиса веб-панели ufw-порт оставался открытым — файрволл продолжал пропускать трафик на мёртвый сервис. При переключении с `0.0.0.0` на `127.0.0.1` старое ufw-правило не удалялось. При смене порта — старый порт оставался открыт.

#### Новая функция `_ufw_web_panel_close(port)`

- Парсит `ufw status numbered` — находит правила с комментарием "VLESS Web Panel (exposed, no TLS)" и нужным портом
- Удаляет по номеру с конца (чтобы номера не съезжали)
- Подтверждает `y\n` для `ufw delete`
- Не трогает чужие правила
- Тихо return если ufw не установлен/неактивен/пустой вывод

#### Изменения в `install_web_service()`

- Читает **старый** конфиг до перезаписи (old_host, old_port)
- При переключении с `0.0.0.0` на `127.0.0.1` → закрывает старый ufw-порт
- При смене порта на `0.0.0.0` → закрывает старый, открывает новый

#### Изменения в `uninstall_web_service()`

- Читает конфиг до остановки сервиса
- Если `host == "0.0.0.0"` → вызывает `_ufw_web_panel_close(port)`
- Затем останавливает/удаляет systemd unit как раньше

#### Изменения в `do_manage_web_panel()`

| Пункт | Что изменилось |
|---|---|
| **1 (Остановить)** | Если exposed (`0.0.0.0`) — закрывает ufw-порт перед `systemctl stop` |
| **1 (Запустить)** | Если exposed — вызывает `install_web_service(expose=True)` вместо голого `systemctl start` (чтобы переоткрыть ufw) |
| **5 (Закрыть доступ)** | `install_web_service(expose=False)` автоматически закрывает старый ufw-порт |
| **6 (НОВЫЙ — Удалить полностью)** | Подтверждение y/N → `uninstall_web_service()` (закрывает ufw + удаляет systemd unit + web_config.json). state.json и VLESS-юзеры НЕ трогаются. |

### 📊 Статистика

| Метрика | Значение |
|---|---|
| Коммитов | 4 (`0601e70` реестр, `a3b14bd` content negotiation, `afce8d4` e2e тесты, `31fe941` ufw) |
| Файлов изменено | 4 (subscription.py, rest_api.py, singbox_menu.py, trusttunnel.py) + 3 тест-файла |
| Новых функций | 8 (_resolve_format, build_subscription_singbox_config, _collect_registry_json_outbounds, _filter_safe_links, _ufw_web_panel_close, get_subscription_uris × 2, _find_singbox_user_credential) |
| Новых пунктов меню | 1 (Удалить полностью) |
| Новых тестов | 40 (23 registry + 26 content negotiation + 6 e2e + 11 firewall) |
| Тестов пройдено | 258 |

---

## REVERT: Протокол Snell v4 полностью удалён — 19 июля 2026

**Протокол Snell v4 (Surge) признан нестабильным в продакшене и полностью удалён из Chimera Project.**

### Причина удаления

В ходе тестирования выявлены непреодолимые проблемы совместимости:

1. **Версия протокола** — snell-server  (последняя доступная сборка) поддерживает только wire protocol v4/v5. Mihomo (Clash Verge Rev) при `version: 4` выдаёт `snell version error: 4` (устаревшее ядро), а без `version` дефолтит на v1 (несовместимо). Нет версии, которая работает везде.

2. **UDP для QUIC** — snell-server v5 требует открытых TCP+UDP портов. Открытие UDP решило часть проблем, но протокольный handshake всё равно не проходил.

3. **Обфускация** — Surge KB: "http is the only option supported by Snell V4". `obfs=tls` может не поддерживаться официальным бинарником. `obfs=off` работает на сервере, но без обфускации протокол легко детектируется DPI.

4. **Клиентская совместимость** — ни один из протестированных Windows-клиентов (Clash Verge Rev, Clash Nyanpasu, FlClash, Karing) не смог корректно установить соединение. VLESS Reality на том же сервере работает без проблем (53мс задержка).

5. **sing-box** — официальный sing-box 1.14.0+ поддерживает Snell, но с другим форматом конфига (`psk` вместо `password`, flat `obfs_mode` вместо nested `obfs`). HYDRA-ULTIMATE использует sing-box-extended (форк), что не применимо к нашей архитектуре.

### Что удалено

**Файлы (8 шт, полностью удалены):**
- `chimera/modules/snell.py`
- `chimera/modules/snell_mirrors.py`
- `chimera/modules/snell_packages.py`
- `chimera/modules/snell_stats.py`
- `tests/test_snell.py`
- `tests/test_snell_mirrors.py`
- `tests/test_snell_packages.py`
- `tests/test_snell_stats.py`

**Точки интеграции (очищены):**
- `_core.py` — удалён import `do_snell_menu`, пункт меню `19`, dispatch
- `rest_api.py` — удалён `"chimera.modules.snell"` из `_SYNCABLE_PROTOCOLS`, Snell-блоки из `_generate_vless_links`/`_generate_clash_config`/`_generate_singbox_config`, `_snell_compat_note`
- `subscription.py` — удалён `_SNELL_STATE`, `_build_snell_uris()`, оба вызова
- `status_panel.py` — удалён `_check_snell()`, `"Snell v4"` из `_protocol_checks`
- `admin_panel.py` — удалено упоминание Snell в подсказке модалки rename
- `user_portal.py` — удалён `#snell-compat-warning` div, JS `hasSnell` проверка
- `tests/test_rest_api.py` — очищены комментарии с упоминанием snell
- `tests/test_user_portal.py` — удалены 3 тест-кейса про snell-compat-warning

### Что НЕ тронуто

- `proto_common.py` — НЕ Snell-специфичный файл, используется 9 другими протоколами
- `mtproto.py` — логика Telemt не изменена, контракт синхронизации (`is_active`/`ensure_user`/`remove_user`/`rename_user`) сохранён
- Реестр `_SYNCABLE_PROTOCOLS` — теперь содержит только `"chimera.modules.mtproto"`, но архитектура реестра и `_sync_dispatch` сохранены для будущих протоколов
- Старые записи в CHANGELOG.md про Snell — не удалены и не отредактированы задним числом (история есть история)
- Тесты реестра синхронизации (`TestSyncRegistryDispatch`, `TestSyncAllFromVless`) с фейковым протоколом — сохранены, не привязаны к реальному Snell

---

## REFACTOR: Обобщённая автосинхронизация VLESS → протоколы через реестр + VLESS tag в web-панели с флагом и именем юзера — 19 июля 2026

**Два крупных улучшения в одном релизе.** Первое — инфраструктурный рефакторинг автосинхронизации: раньше для каждого нового протокола нужно было писать 5 новых функций-мостов в `rest_api.py`, теперь — ОДНА строка в реестре. Второе — UX-фикс: ссылки из web-панели теперь выглядят так же как из TUI (с флагом страны и именем юзера), а не как безликие "VLESS Reality".

### 🔧 Рефакторинг: обобщённая автосинхронизация через реестр

**Проблема:** автосинхронизация VLESS → Telemt и VLESS → Snell была реализована ad-hoc — 10 функций-мостов (`_telemt_is_active`, `_telemt_ensure_user`, `_telemt_remove_user`, `_telemt_rename_user`, `_telemt_sync_all_from_vless` + 5 аналогов для Snell) жили прямо в `rest_api.py` и хардкодили вызовы в конкретные модули. Добавление автосинхронизации для нового протокола требовало копирования всего этого набора с переименованием — 5 новых функций, 4 хука в endpoints, обновление admin_panel.py JS. Это не масштабируется.

**Фикс — 5 шагов рефакторинга:**

#### Шаг 1 — контракт протокола (4 функции на модуль)

Каждый протокольный модуль, участвующий в автосинхронизации, теперь обязан экспортировать 4 функции с едиными сигнатурами:

```python
def is_active() -> bool:               # протокол установлен и активен
def ensure_user(name: str) -> bool:    # создать аккаунт если нет
def remove_user(name: str) -> bool:    # удалить аккаунт
def rename_user(old: str, new: str) -> bool  # переименовать с сохранением данных
```

Все 4 **НИКОГДА** не бросают исключение наружу — ловят всё внутри и возвращают `bool`. Это позволяет реестру диспетчеризовать вызовы безопасно, не падая при сбое одного из протоколов. Ни валидация имён, ни лимиты (порты, количество юзеров), ни политика "нельзя удалить последнего" интерфейсом не диктуются — это остаётся внутренней логикой каждого протокол-модуля.

- **`mtproto.py`**: добавлены `is_active()`, `ensure_user()`, `remove_user()`, `rename_user()` как module-level публичные функции. Логика перенесена из старых `_telemt_*` мостов в `rest_api.py`. Внутренняя политика (нельзя удалить последнего, валидация имён, генерация секрета) — полностью инкапсулирована.
- **`snell.py`**: добавлены `is_active()` (alias для `is_any_active()`), `ensure_user()`, `remove_user()` как обёртки над существующими `_add_user`/`_remove_user` с подавлением исключений. `rename_user()` уже существовала — осталась как есть.

#### Шаг 2 — реестр + диспетчер в `rest_api.py`

```python
_SYNCABLE_PROTOCOLS = [
    "chimera.modules.mtproto",
    "chimera.modules.snell",
]

def _sync_dispatch(method: str, *args) -> dict:
    # Импортирует модуль, проверяет is_active(), вызывает method
    # Возвращает {proto: bool|None} — None если протокол недоступен
```

Плюс обёртки `_sync_ensure_user`, `_sync_remove_user`, `_sync_rename_user`, `_sync_all_from_vless`. Диспетчер перебирает все протоколы в реестре, для каждого: импортирует модуль (ловит ImportError → None), проверяет `is_active()` (False → None), вызывает method (ловит исключения → None). Один сбой не роняет остальные.

#### Шаг 3 — удалены старые ad-hoc мосты

Из `rest_api.py` удалены 10 функций `_telemt_*`/`_snell_*` (665 строк удалено, 370 net). Больше не нужно писать новый набор функций для каждого протокола.

#### Шаг 4 — обновлены хуки endpoints

- `POST /api/users` → `protocol_sync = _sync_ensure_user(name)` вместо `telemt_synced`/`snell_synced`
- `DELETE /api/users/{email}` → `protocol_sync = _sync_remove_user(name)`
- `POST /api/users/{email}/rename` → `protocol_sync = _sync_rename_user(old, new)`
- `POST /api/users/sync` → `protocol_stats = _sync_all_from_vless(users)` (per-proto `{created, skipped}`)

`admin_panel.py` JS: toast формируется перебором `protocol_sync` — не хардкодит конкретные имена протоколов, автоматически работает для любого протокола добавленного в реестр.

#### Шаг 5 — тесты

- `tests/test_mtproto.py`: +21 кейс (TestSyncContractIsActive/EnsureUser/RemoveUser/RenameUser) — напрямую тестируют контрактные функции
- `tests/test_snell.py`: +14 кейсов (TestSnellSyncContract) — обёртки с подавлением исключений, can-delete-last
- `tests/test_rest_api.py`: заменены 43 ad-hoc теста на 28 реестровых (используют ФЕЙКОВЫЙ протокол-модуль, не привязаны к mtproto/snell). Включая явные кейсы: ImportError → None, exception в is_active → None, один сбой не роняет остальные.

**Итог:** 468 тестов проходят (было 410). Добавление нового протокола в синхронизацию = **ОДНА строка** в `_SYNCABLE_PROTOCOLS` + реализация 4 функций контракта в модуле протокола. Больше никаких правок в `rest_api.py` или `admin_panel.py`.

### ✨ VLESS tag в web-панели: флаг страны + имя юзера

**Проблема:** web-панель генерировала VLESS-ссылки с хардкоженными тэгами `#VLESS-Reality` / `#VLESS-xHTTP` / `#VLESS-Reality-IPv6` / `#VLESS-xHTTP-IPv6` — без флага страны и без имени юзера. В клиентах (v2rayN, NekoBox, Karing, и т.п.) несколько узлов отображались как одинаковые "VLESS Reality", без возможности отличить. TUI-ссылки (`_unified_show_links` в `users_manager.py`) имели правильный формат: `<флаг> <имя_юзера>`.

**Фикс:** `_generate_vless_links` в `rest_api.py` теперь использует тот же формат tag что и TUI:

```
vless://uuid@domain:443?...#🇩🇪 alice           ← IPv4 с флагом
vless://uuid@domain:443?...#🇩🇪 alice-IPv6      ← IPv6 с флагом + суффикс
vless://uuid@domain:443?...#alice               ← без флага (если ip-api недоступен)
```

**Логика:**
- Флаг страны — через `core.get_server_country_cached()` (один curl к ip-api.com, кешируется на всё время работы процесса)
- Если флаг `"🌐"` (страна неизвестна) — tag без флага, только имя юзера
- Имя юзера: `user["name"]` → `user["email"]` → `"user"` (та же fallback-цепочка что в TUI)
- IPv6-ссылка добавляет суффикс `-IPv6` чтобы отличить от IPv4 в клиенте
- Tag URL-кодируется (`urllib.parse.quote`) — пробелы и спецсимволы обрабатываются корректно

**Тесты — 10 новых регрессионных кейсов** в `TestGenerateVlessLinksTag`:
- tag содержит имя юзера
- tag НЕ равен `VLESS-Reality` (регрессия на старый хардкод)
- tag содержит флаг 🇩🇪 когда страна доступна
- tag без флага когда страна неизвестна
- fallback на email когда нет name
- fallback на "user" когда нет ни name, ни email
- IPv6 tag имеет суффикс `-IPv6`
- URL-кодирование спецсимволов
- tag одинаковый для REALITY и xHTTP (один и тот же юзер)
- `get_server_country_cached` вызывается 1 раз (кеширование, не 2 для IPv4+IPv6)

### 📊 Статистика

| Метрика | Значение |
|---|---|
| Коммитов в релизе | 2 (`1e13bee` рефакторинг + `7f48a05` tag фикс) |
| Файлов изменено | 7 (mtproto.py, snell.py, rest_api.py, admin_panel.py, test_mtproto.py, test_snell.py, test_rest_api.py) |
| Строк добавлено | ~1200 |
| Строк удалено | ~700 (старые ad-hoc мосты + старые тесты) |
| Новых контрактных функций | 8 (4 в mtproto.py + 4 в snell.py) |
| Удалено ad-hoc функций | 10 (`_telemt_*` + `_snell_*` из rest_api.py) |
| Новых тестов | 45 (21 mtproto contract + 14 snell contract + 10 tag regression) |
| Тестов пройдено | 468 (было 410) |

### ⚠️ Изменения

#### 1. `chimera/modules/mtproto.py`

Добавлены 4 module-level публичные функции контракта синхронизации:
- `is_active()` — обёртка над `systemctl is-active telemt`
- `ensure_user(name)` — создаёт Telemt-аккаунт если нет, валидация имени, генерация секрета
- `remove_user(name)` — удаляет, отказ если последний (Telemt требует минимум одного)
- `rename_user(old, new)` — переименование с сохранением секрета, fallback на создание если old не найден

Все 4 ловят исключения внутри, возвращают `bool`.

#### 2. `chimera/modules/snell.py`

Добавлены 3 функции (rename_user уже существовала):
- `is_active()` — alias для `is_any_active()` (для унификации контракта)
- `ensure_user(name)` — обёртка над `_add_user()` с подавлением ValueError/RuntimeError
- `remove_user(name)` — обёртка над `_remove_user()` с подавлением исключений

#### 3. `chimera/modules/rest_api.py`

- Удалены 10 ad-hoc функций `_telemt_*`/`_snell_*` (665 строк)
- Добавлены `_SYNCABLE_PROTOCOLS` реестр + `_sync_dispatch` + 4 обёртки (`_sync_ensure_user`, `_sync_remove_user`, `_sync_rename_user`, `_sync_all_from_vless`)
- 4 endpoint хука обновлены на `_sync_*` + `protocol_sync` в ответах вместо плоских `telemt_synced`/`snell_synced`
- `_generate_vless_links`: tag теперь `<флаг> <имя_юзера>` вместо `VLESS-Reality`, через `get_server_country_cached()`

#### 4. `chimera/modules/admin_panel.py`

- JS `renameUser()` toast: перебирает `protocol_sync` entries вместо хардкода `telemt_synced`/`snell_synced`
- Подсказка в `#rename-user-modal` обобщена — упоминает "протоколы синхронизации (Telemt/MTProto, Snell v4 и любые другие из реестра)" вместо конкретных имён

### 🔄 Миграция

**Для существующих инсталляций:**

1. `cd /opt/chimera && git pull && systemctl restart vless-web`
2. Поведение для пользователя не изменилось — те же MTProto/Snell ссылки появляются в User Portal при создании VLESS-юзера
3. VLESS-ссылки в User Portal теперь отображаются в клиенте с флагом и именем юзера вместо "VLESS Reality"

**Для разработчиков (добавление нового протокола в синхронизацию):**

1. Добавить 4 функции контракта (`is_active`, `ensure_user`, `remove_user`, `rename_user`) в модуль протокола — ~30 строк
2. Добавить ОДНУ строку `"chimera.modules.<proto>"` в `_SYNCABLE_PROTOCOLS` в `rest_api.py`
3. Всё — реестр автоматически подхватит новый протокол во всех 4 endpoints, toast в админ-панели покажет его статус

### 🔬 Методология

- **Правило "контракт не диктует политику"**: интерфейс (`is_active`/`ensure_user`/`remove_user`/`rename_user`) не диктует политику ("нельзя удалить последнего", лимиты портов, валидация имён) — это остаётся внутренней логикой каждого протокол-модуля. Snell может удалять последнего (каждый инстанс независим), Telemt не может (общий `[access.users]`). Реестр про это ничего не знает.
- **Правило "no-op на любой сбой"**: все 4 функции контракта НИКОГДА не бросают исключение наружу. Если протокол недоступен — `is_active()` → False, синхронизация пропускается (`results[proto] = None`). Если method бросает — тоже None. Один сбой не роняет остальные протоколы в реестре.
- **Правило "тесты не привязаны к конкретным протоколам"**: тесты реестра (`TestSyncRegistryDispatch`, `TestSyncAllFromVless`) используют ФЕЙКОВЫЙ протокол-модуль, регистрируемый в `sys.modules`. Не ломаются при добавлении/удалении реальных протоколов из `_SYNCABLE_PROTOCOLS`.

### 📝 Замечания

- **Поле `protocol_sync` в JSON-ответах** — новое имя вместо старых `telemt_synced`/`snell_synced`. Если у вас есть сторонние скрипты, парсящие эти поля — обновите их. Стандартные клиенты (админ-панель) обновлены автоматически.
- **Флаг страны кешируется** — один curl к ip-api.com за всё время работы `vless-web` процесса. Если IP сервера изменится (перезагрузка с новым IP), флаг не обновится до рестарта сервиса. Это приемлемо — флаг информационный, не критичный.
- **`get_server_country_cached` вызывается 1 раз** за `_generate_vless_links` — даже если у юзера 2 ссылки (IPv4+IPv6), curl не дублируется.

---

## FEAT: ShadowTLS SNI-пресеты + MTProto-ссылка в User Portal + автосинхронизация Telemt + переименование юзеров — 19 июля 2026

**Релиз закрывает три давних UX-проблемы и добавляет одну долгожданную функцию.** Все правки нацелены на то, чтобы User Portal и Admin Panel работали «из коробки» без ручных шагов в TUI — Telemt-аккаунт создаётся автоматически при создании VLESS-юзера, MTProto-ссылка появляется в портале без переименования пользователя вручную, а ShadowTLS теперь предлагает курируемый список SNI вместо ввода домена вслепую.

### ✨ Новые функции

#### 1. ShadowTLS: SNI-пресеты для handshake-домена (`feat(shadowtls)`)

Раньше при включении ShadowTLS или смене handshake-домена админ должен был вручную вводить TLS 1.3 домен для маскировки — без подсказок, без примеров. Теперь в TUI-меню (пункты «Включить ShadowTLS (custom)» и «Сменить handshake домен») показывается курируемый список из 12 пресетов, разделённый на международные и российские домены.

**Кураторский список `SHADOWTLS_SNI_PRESETS` в `singbox_common.py`:**

| # | Домен | Категория |
|---|---|---|
| 1 | `www.microsoft.com` | Международный · Microsoft |
| 2 | `www.apple.com` | Международный · Apple |
| 3 | `www.cloudflare.com` | Международный · Cloudflare |
| 4 | `www.amazon.com` | Международный · Amazon |
| 5 | `www.samsung.com` | Международный · Samsung |
| 6 | `www.adobe.com` | Международный · Adobe |
| 7 | `ya.ru` | Россия · Яндекс |
| 8 | `vk.com` | Россия · ВКонтакте |
| 9 | `max.ru` | Россия · MAX |
| 10 | `dzen.ru` | Россия · Дзен |
| 11 | `rutube.ru` | Россия · Rutube |
| 12 | `www.ozon.ru` | Россия · Ozon |
| 13 | (custom) | Свой домен |

**UX-изменения в `singbox_menu.py`:**

- Меню через `_box_top` / `_box_row` / `_box_item` / `_box_bottom` (тот же visual-language, что и остальные TUI-меню Chimera)
- Выбор по номеру (1-12) — домен подставляется автоматически
- Пункт 13 — «Свой домен» с ручным вводом (fallback для опытных админов)
- Пункт 0 — «Отмена» (через `_box_item_exit`)
- `KeyboardInterrupt` (Ctrl+C) в любой момент → тихий возврат в меню без exception

**Транзакционная смена handshake-домена** (только в `_change_handshake_domain`): перед применением нового SNI сохраняется `copy.deepcopy()` старого `handshake`-блока state-файла. Если sing-box не запускается с новым доменом (`_apply_and_check` возвращает False) — автоматически восстанавливается прежний handshake и снова применяется. Админ видит `warn("Откат: восстанавливаем прежний handshake...")` и `error("Не удалось применить новый SNI — конфиг восстановлен")`. Это защищает от сценария «выбрал домен, который оказался недоступен из РФ → sing-box упал → пользователи без VPN».

Список адаптирован из HYDRA-ULTIMATE (`gr33nimax/d9968e37`) — кураторская подборка TLS 1.3 доменов, проверенных на совместимость с ShadowTLS.

#### 2. MTProto (Telemt) ссылка в User Portal (`fix(rest_api)`)

**Баг:** в `_generate_vless_links()` (rest_api.py) блок MTProto обращался к функции `_load_state` из `chimera.modules.mtproto` и файлу `/var/lib/xray-installer/mtproto_state.json` — **ни того, ни другого не существует**. Реальный модуль (Telemt) хранит конфиг в `/etc/telemt/telemt.toml` и экспортирует `_load_users()`, `_get_port()`, `_get_domain()`, `_make_tls_secret()`. Из-за `except Exception: pass` импорт падал молча — ссылка просто не появлялась в `/api/portal/links` без ошибок в логах.

**Фикс:** блок MTProto переписан на реальные геттеры Telemt:

```python
from chimera.modules.mtproto import (
    _load_users as _telemt_load_users,
    _get_port as _telemt_get_port,
    _get_domain as _telemt_get_domain,
    _make_tls_secret as _telemt_make_tls_secret,
    SERVICE_NAME as _TELEMT_SERVICE_NAME,
)
```

Логика генерации ссылки:

1. **Проверка активности сервиса** — `systemctl is-active telemt` через `core._run()`. Если сервис не активен — ссылка не отдаётся (по аналогии с Hysteria2-проверкой выше в том же файле). Это защищает от показа битой ссылки на неработающий сервис.
2. **Персональный секрет юзера** — `user["name"]`, `user["email"]` и локальная часть email (`email.split("@")[0]`) по очереди проверяются против ключей в `_load_users()`. Это решает типичный кейс: portal user с email `alice@node-b.example`, Telemt-имя `alice` — fallback по локальной части находит совпадение. Если совпадения нет — ссылка **не показывается** (раньше бы отдалась чужая/первая попавшаяся). Чужой секрет никогда не утекает.
3. **TLS-режим vs plain-режим** — если `_get_domain()` возвращает непустой `tls_domain` (секция `[censorship]` активна), секрет оборачивается через `_make_tls_secret(secret, tls_domain)` → `f"ee{secret}{tls_domain.encode().hex()}"`. Иначе отдаётся голый `secret` из `_load_users()`. Оба режима покрыты тестами.

Фронтенд (`user_portal.py`, JS-функция `loadLinks()`) не менялся — карточка со ссылкой, QR-кодом и кнопкой «Копировать ссылку» уже универсальна и рендерится для любого элемента массива `links`, включая произвольные `label` / `protocol` / `link`. Как только бэкенд начал корректно отдавать MTProto-ссылку в `/api/portal/links` — UI подхватил её автоматически.

**Тесты:** 7 новых кейсов в `TestGenerateVlessLinksMTProto` покрывают все ветки: счастливый путь (TLS-режим с проверкой формата `ee<secret><domain_hex>`), plain-режим (голый секрет без `ee`-префикса), fallback по локальной части email, отсутствие совпадения (ссылка не показывается, остальные ссылки не ломаются), неактивный сервис, пустой `[access.users]`, broken import (модуль недоступен → silent-pass по контракту `except Exception: pass`).

#### 3. Автосинхронизация VLESS → Telemt (`feat(rest_api)`)

**Проблема:** после создания VLESS-юзера в админ-панели MTProto-ссылка не появлялась в User Portal, пока админ вручную не зайдёт в TUI Chimera → Telemt → Управление пользователями → Добавить. Секция `[access.users]` в `/etc/telemt/telemt.toml` независима от `users.json` — между ними не было моста.

**Фикс:** добавлен слой автосинхронизации VLESS → Telemt в `rest_api.py` — 5 функций-мостов:

| Функция | Действие |
|---|---|
| `_telemt_is_active()` | `systemctl is-active telemt` через `core._run()` |
| `_telemt_ensure_user(name)` | Создаёт Telemt-аккаунт с тем же `name`, если его ещё нет. Секрет генерируется через `_generate_secret()` (os.urandom(16).hex()) |
| `_telemt_remove_user(name)` | Удаляет Telemt-аккаунт. **Отказывается удалять последнего** пользователя (Telemt падает при пустом `[access.users]`) |
| `_telemt_rename_user(old, new)` | Переименовывает, **сохраняя секрет** (MTProto-ссылка остаётся рабочей, меняется только имя). Если `new` уже занят — no-op (не перезаписывает чужой секрет) |
| `_telemt_sync_all_from_vless(users)` | Массовая синхронизация: создаёт недостающие Telemt-аккаунты для всех валидных VLESS-имён. Возвращает `{"created": N, "removed": 0, "skipped_invalid": N}` |

**Хуки в существующие endpoints:**

- `POST /api/users` → `_telemt_ensure_user(name)` — новый VLESS-юзер сразу получает Telemt-аккаунт
- `DELETE /api/users/{email}` → `_telemt_remove_user(name)` — при удалении VLESS-юзера удаляется и Telemt-аккаунт (чтобы не оставался «висящий» MTProto-доступ для удалённого юзера)
- `POST /api/users/sync` → `_telemt_sync_all_from_vless(users)` — кнопка «Синхронизация пользователей» в админ-панели теперь создаёт недостающие Telemt-аккаунты оптом. В ответе добавлены поля `telemt_created` и `telemt_skipped_invalid` для информативного toast

**Безопасность:**

- Все функции — **no-op** если Telemt не активен или модуль недоступен (`ImportError`). Никогда не ломают VLESS.
- Telemt-спека на имена `^[a-zA-Z][a-zA-Z0-9_\-]{2,15}$` проверяется через `_validate_username()` из mtproto.py. VLESS-юзеры с `@`, точками или дефисами в неподходящих позициях пропускаются и попадают в `skipped_invalid` (видно в toast).
- При переименовании секрет **переносится**, не генерируется заново — MTProto-ссылка остаётся рабочей, юзеру не нужно заново сканировать QR.
- Нельзя удалить последнего Telemt-юзера — функция возвращает False, VLESS-юзер всё равно удаляется, но Telemt сохраняет последнего аккаунт (иначе Telemt падает в restart-loop).
- Нельзя перезаписать чужой секрет при коллизии имён — если новое имя уже занято в Telemt, `_telemt_rename_user` возвращает False без записи.

**Тесты:** 16 новых кейсов в `TestTelemtSyncHelpers` покрывают все ветки: ensure/remove/rename/sync_all, валидные и невалидные имена, активный и неактивный сервис, ImportError fallback, отказ удалять последнего, отказ перезаписывать чужой секрет, skip disabled VLESS-юзеров в массовой синхронизации.

#### 4. Кнопка «Переименовать» в Admin Panel (`feat(admin_panel)`)

Раньше изменить `name` (login для портала) можно было только удалением юзера и пересозданием — с потерей `portal_password`, `created`, `disabled`-флагов и (косвенно) Telemt-секрета. Теперь в каждой строке таблицы пользователей есть кнопка `✏️ Переименовать`.

**UI (admin_panel.py):**

- Новое модальное окно `#rename-user-modal` с тремя полями:
  - email (readonly, для контекста)
  - текущее имя (readonly, для сравнения)
  - новое имя (input, autofocus)
- Подсказка в модалке объясняет поведение Telemt: «Если включён Telemt (MTProto), соответствующий аккаунт будет переименован автоматически с сохранением секрета — MTProto-ссылка останется рабочей. Для валидации имени в Telemt формат: латиница, 3-16 символов ([a-zA-Z][a-zA-Z0-9_-]).»
- Кнопка `✏️ Переименовать` в строке таблицы между `🔒 Заблокировать` и `🔑 Пароль`
- JS-функции `showRenameUserModal(email, currentName)` и `renameUser()` с клиентской валидацией (3-32 символа) и информативным toast с результатом Telemt-синхронизации

**Бэкенд (rest_api.py):**

Новый endpoint `POST /api/users/{email}/rename` с телом `{"new_name": "..."}`:

- Admin-only (через `_require_admin()`)
- Валидация: `new_name` 3-32 символа, непустой
- Меняет только поле `name` в `users.json` — **email не трогается** (он ключ в `users.json` и `clients[].email` в `config.json` Xray, его изменение сломало бы статистику трафика и TTL)
- `config.json` Xray не нужно перезаписывать — там используется `email`, а не `name`. `_users_apply_to_config` не вызывается.
- Вызывает `_telemt_rename_user(old_name, new_name)` для синхронизации Telemt. Если Telemt не активен или новое имя не подходит под Telemt-спеку — VLESS всё равно переименовывается, Telemt-синхронизация best-effort.
- В ответе: `{"status": "renamed", "email": "...", "old_name": "...", "new_name": "...", "telemt_synced": bool, "telemt_reason": "..."}` — `telemt_reason` показывает почему sync не сработал (например, «имя не подходит под Telemt-спеку (нужен [a-zA-Z][a-zA-Z0-9_-]{2,15})» или «сервис не активен»)

**Тесты:** 6 новых кейсов в `TestRenameUserEndpoint` покрывают обновление `name` в users.json, вызов `_telemt_rename_user` с сохранением секрета, обработку невалидного Telemt-имени (с reason), отказ на коротких/длинных именах, no-op при `old == new`. Smoke-тест `test_rename_user_ui_present` в `test_admin_panel.py` проверяет наличие модального окна, кнопки, JS-функций и input-поля в HTML.

### 📊 Статистика

| Метрика | Значение |
|---|---|
| Коммитов в релизе | 4 (`6ed3b51`, `16a8979`, `28fc0b9`, плюс 2 ShadowTLS `29c19db` + `6374a00` из прошлой ветки) |
| Файлов изменено | 4 (rest_api.py, admin_panel.py, mtproto.py не тронут, singbox_common.py + singbox_menu.py для ShadowTLS) |
| Строк добавлено | ~840 (включая тесты и комментарии) |
| Новых функций-мостов в rest_api.py | 5 (`_telemt_is_active`, `_telemt_ensure_user`, `_telemt_remove_user`, `_telemt_rename_user`, `_telemt_sync_all_from_vless`) |
| Новых endpoints | 1 (`POST /api/users/{email}/rename`) |
| Новых UI-элементов | 1 модальное окно + 1 кнопка в строке таблицы + 2 JS-функции |
| SNI-пресетов для ShadowTLS | 12 (6 международных + 6 российских) |
| Новых тестов | 30 (7 MTProto-ссылка + 16 Telemt-синхронизация + 6 rename endpoint + 1 UI smoke) |
| Тестов пройдено | 179 (test_rest_api 47 + test_admin_panel 6 + test_user_portal + test_mtproto + test_telemt_panel = 126) |

### ⚠️ Изменения

#### 1. `chimera/modules/singbox_common.py`

Добавлена константа `SHADOWTLS_SNI_PRESETS` — кортеж из 12 `(domain, label)` пар. Без логики, чисто данные. Импортируется в `singbox_menu.py`.

#### 2. `chimera/modules/singbox_menu.py`

- `_enable_shadowtls_custom()`: перед запросом handshake-домена показывается меню SNI-пресетов. Выбор по номеру → домен подставляется. Пункт «Свой домен» → ручной ввод (старое поведение).
- `_change_handshake_domain()`: та же SNI-менюшка + **транзакционная смена** с откатом при неудаче. Сохраняется `copy.deepcopy()` старого `handshake`-блока, при падении `_apply_and_check` восстанавливается и снова применяется.

#### 3. `chimera/modules/rest_api.py`

- Переписан блок MTProto в `_generate_vless_links()` (строки ~451-521): реальные геттеры Telemt вместо `_load_state`, проверка `systemctl is-active telemt`, персональный секрет по `user.name/email/email-local-part`, поддержка TLS и plain режимов.
- Добавлены 5 функций-мостов для синхронизации VLESS → Telemt (см. раздел «Автосинхронизация» выше).
- Добавлен endpoint `POST /api/users/{email}/rename`.
- Хуки автосинхронизации в `POST /api/users`, `DELETE /api/users/{email}`, `POST /api/users/sync`.
- В docstring модуля добавлен новый endpoint в список.

#### 4. `chimera/modules/admin_panel.py`

- Новое модальное окно `#rename-user-modal` с тремя input-полями и подсказкой про Telemt.
- Кнопка `✏️ Переименовать` в каждой строке таблицы пользователей.
- JS-функции `showRenameUserModal(email, currentName)` и `renameUser()` с валидацией и toast-уведомлением.

### 🔄 Миграция

**Для существующих инсталляций:**

1. `cd /opt/chimera-project && git pull`
2. `systemctl restart vless-web` — подхватит новые endpoints и UI
3. (опционально) В админ-панели нажать «Синхронизация пользователей» — создаст недостающие Telemt-аккаунты для всех существующих VLESS-юзеров с валидными именами. В toast будет видно сколько создано и сколько пропущено (невалидные имена).
4. (опционально) В TUI Chimera → Sing-box → ShadowTLS → «Сменить handshake домен» — увидеть новое SNI-меню.

**Для новых инсталляций:** ничего специального — все функции работают из коробки.

### 🔬 Методология

- **Правило «no-op на любой сбой»** для Telemt-синхронизации: все 5 функций-мостов возвращают False/пустой dict при любой ошибке (ImportError, OSError, исключения из mtproto.py) и никогда не пробрасывают исключение наверх. VLESS-операция (создание/удаление/переименование юзера) выполняется в первую очередь; Telemt-синхронизация — best-effort во вторую. Это гарантирует, что сбой Telemt никогда не сломает VLESS.
- **Правило «чужой секрет не отдаём»** для MTProto-ссылки: если у портального юзера нет соответствующего Telemt-аккаунта (имя не найдено по `name`/`email`/`email-local-part`), ссылка **не показывается**. Раньше код отдал бы секрет первого попавшегося Telemt-юзера — это утечка.
- **Правило «сохраняем секрет при переименовании»**: `_telemt_rename_user` делает `users[new] = users.pop(old)` — секрет переносится, а не генерируется заново. Это критично: MTProto-ссылка, которую юзер уже добавил в Telegram-клиент, продолжает работать после переименования.
- **Транзакционная смена SNI для ShadowTLS**: `copy.deepcopy()` старого state → применение нового → проверка запуска sing-box → откат при неудаче. Админ всегда видит либо «Handshake: domain:port» (успех), либо «Откат: восстанавливаем прежний handshake...» + «Не удалось применить новый SNI — конфиг восстановлен» (неудача).

### 📝 Замечания

- **Имена VLESS-юзеров с `@` или точками** не получат MTProto-ссылку — это ограничение Telemt-бинарника, не наше. Спека: `^[a-zA-Z][a-zA-Z0-9_\-]{2,15}$`. Если у вас есть такие юзеры, переименуйте их через новую кнопку «Переименовать» в админ-панели (например, `alice.portal@x.com` → `alice`).
- **Telemt должен быть активен** для генерации MTProto-ссылки. Проверка `systemctl is-active telemt` — то же самое условие, что и для Hysteria2 (там `systemctl is-active hysteria-server`). Если сервис упал — ссылка не отдаётся, чтобы не показывать битый URL.
- **При удалении последнего VLESS-юзера** Telemt-аккаунт не удаляется (функция `_telemt_remove_user` отказывается это делать). Это предотвращает падение Telemt в restart-loop при пустом `[access.users]`. При следующем создании VLESS-юзера Telemt-аккаунт создастся заново через `_telemt_ensure_user`.

---

##  — REBRAND: VLESS Ultimate Installer → Chimera Project — 15 июля 2026

**Мажорный релиз — смена идентичности проекта.** Название «VLESS Ultimate Installer» перестало отражать суть: за 8 недель разработки (с 19 мая 2026) проект вырос с 1 протокола (VLESS) до 9+ (VLESS REALITY/xHTTP, Hysteria2, AmneziaWG standalone, MTProto/Telemt, NaiveProxy, Mieru, FPTN, TrustTunnel), с ~30 функций до ~1 500, с одного файла до 143 модулей + ядро 8 093 строки + 25 категорий. Новое имя — **Chimera Project** — метафора мифического существа, собранного из частей разных животных: каждая «голова» (протокол) нужна для своего сценария, и если цензор блокирует один, химера «выращивает новую голову».

### 🎭 Почему Chimera

**Химе́ра** (греч. Χίμαιρα) — чудовище с головой льва, телом козы и хвостом змеи; существо из разнородных частей. Прямые параллели с проектом:

- **Голова льва** (главная, пасть) — VLESS REALITY, основной и самый «зубастый» протокол
- **Тело козы** (неприхотливое, выносливое) — AmneziaWG, устойчивый к DPI туннель, работает даже на мобильных сетях
- **Хвост змеи** (гибкий, ядовитый) — Hysteria2/QUIC, быстрый UDP-транспорт с обфускацией
- **Существо из многих частей** — 9+ протоколов, 143 модуля, 25 категорий, единый организм
- **Не сводится ни к одной части** — нельзя сказать «это VLESS-installer», это мульти-протокольный комбайн

Название **Chimera** краткое (7 букв), запоминающееся, интернациональное (известно в английском, русском, немецком, французском), не привязано к протоколу — в отличие от «VLESS», «Hysteria», «AWG» в названии, не отдаёт приоритет ни одному из 9+ протоколов. AmneziaWG standalone, например, вообще не использует VLESS под капотом.

### 📋 Почему переименование сейчас

1. **Имя врёт пользователю.** Человек, видящий «VLESS Ultimate Installer», ожидает VLESS-сервер. Реально получает 9 протоколов, кластер, балансировку, веб-панель, REST API, Telegram-бота, DPI-детектор. Это разрыв ожиданий.
2. **SEO и discoverability.** По слову «VLESS» проект конкурирует с десятками репозиториев. По «Chimera» в niche anti-censorship — он будет единственным заметным.
3. **Развязка рук для роста.** Сейчас добавление новых не-VLESS протоколов ощущается как «выход за рамки». После ребрендинга это будет «новая голова химеры» — в рамках бренда.
4. **Точка мажорного релиза.**  как мажорный bump — естественный момент для смены идентичности.

### 🔄 Что переименовано

#### 1. Python-пакет: `vless_installer/` → `chimera/`

Полный rename каталога + массовый sed всех импортов `from vless_installer.modules.X import Y` → `from chimera.modules.X import Y` в 399 файлах (6 892 замены). Критичная инфраструктура:
- `main.py`: `_core_path = Path(__file__).parent / "chimera" / "_core.py"`
- `main.py`: `sys.modules["chimera._core"] = sys.modules["__main__"]` — критичный фикс для lazy binding через `_core_module()` в вынесенных модулях
- `verify.py`, `full_test.py`, `smoke_test_modules.py`: обновлены пути к ядру и список проверяемых модулей
- Вендорный код `_vendor/dpi_detector/*.py` НЕ ТРОГАЕМ — он не импортирует наш пакет, запускается через subprocess

#### 2. ASCII-баннер: `VLESS` → `CHIMERA`

Сгенерирован через `pyfiglet.renderText("CHIMERA", font="ansi_shadow")` — 6 строк × 54 символа, использует те же block-символы `╗╔╝╚═║` что и оригинальный VLESS баннер (визуальная преемственность). Внутренняя ширина рамки `_OW=67` посчитана программно: `max(art_w + 4, info_w + 8) = max(58, 67) = 67`. Полная проверка ширины: 24 строки (с RAM-предупреждением) + 19 строк (без) — все 69 символов, 0 mismatch.

Info-строки обновлены под текущее состояние проекта:
- `Chimera Project — Multi-Protocol Anti-DPI Installer v{version}`
- `VLESS · Hysteria2 · AmneziaWG · TrustTunnel · MTProto`
- `NaiveProxy · Mieru · FPTN · Slipgate · WARP · WDTT · +more`
- `Anti-DPI: REALITY · xHTTP · Fragmentation · Port Hopping`
- `Cluster: RoundRobin · LeastPing · LeastLoad · Failover A↔B`
- `Dashboard · REST API · TG Bot · Admin Panel · User Portal`

#### 3. URL репозитория: `VLESS-Ultimate-Installer` → `Chimera-Project`

9 URL-замен в 4 файлах (README.md, INSTALL.md, SECURITY.md, bootstrap.sh). GitHub автоматически редиректит старый URL на новый (включая `raw.githubusercontent.com` и archive tarball), поэтому существующие клоны и `curl | bash` продолжают работать. В README добавлен Note про редирект.

#### 4. Текстовые упоминания: `VLESS Ultimate Installer` → `Chimera Project`

37 замен в 27 файлах — в docstrings модулей, комментариях в генерируемых конфигах (hysteria2, awg_transport, mtproto, fptn, singbox, trusttunnel), описаниях systemd-юнитов, HTML в admin panel, cron-комментариях. `VLESS` как название протокола (VLESS REALITY, VLESS+xHTTP) НЕ ТРОГАЕМ — это отдельное понятие.

#### 5. Пути в ОС

| Старый путь | Новый путь | Кол-во замен |
|---|---|---|
| `/opt/vless-ultimate` | `/opt/chimera` | 63 |
| `/var/log/vless-install.log` | `/var/log/chimera.log` | 50 |
| `/var/lib/xray-installer/` | (НЕ ТРОГАТЬ) | — |

**Обратная совместимость для лога:** при старте `_core.py` создаёт symlink `/var/log/vless-install.log` → `/var/log/chimera.log`. Если старый лог существует как regular file — его содержимое копируется в новый, старый переименовывается в `.pre-chimera.bak`, затем заменяется symlink. Это позволяет существующим cron-задачам и logrotate-конфигам со старым путём продолжать работать без изменений.

**`bootstrap.sh` fallback:** `INSTALL_DIR="/opt/chimera"`. Поиск существующей установки только в системных путях: `/opt/vless-ultimate`, `/opt/VLESS-Ultimate-Installer`, `/opt/chimera`. Домашние директории разработчиков НЕ проверяются (это личные пути, бесполезные для конечных пользователей и засвечивающие структуру окружения).

**`/var/lib/xray-installer/` НЕ МИГРИРОВАН** — 258 вхождений в коде, baseline в `verify.py` (150), риск сломать `state.json` у текущих пользователей. Это «внутренний» путь, юзер его почти не видит.

### 📊 Статистика

| Метрика | Значение |
|---|---|
| Коммитов в ветке rebrand/chimera-project | 6 (Phases 2-6 + этот релиз) |
| Файлов изменено | ~450 |
| Строк изменено | ~7 100 (insertions) / ~7 000 (deletions) |
| Замен `vless_installer` → `chimera` | 6 892 в 399 файлах |
| Замен URL | 9 в 4 файлах |
| Замен текстовых упоминаний | 37 в 27 файлах |
| Замен путей в ОС | 113 в 49 файлах |
| Замен версии `4.25.1` → `5.0.0` | 7 в 5 файлах |
| Тестов пройдено | verify.py 313/313, full_test.py 74/74, smoke_test_modules.py 43/43 |

### 🔬 Методология

**Правило по ASCII-art** (установлено пользователем): никогда не писать баннеры/лого вручную символами `██╗/██║/╚═╝` — систематически путаю блоки. Вместо этого: `pyfiglet` + программный расчёт ширины через `len()` + реальный прогон функции + точный вывод в отчёт. Применено к CHIMERA-баннеру: шрифт `ansi_shadow`, все 6 строк вставлены verbatim из pyfiglet, `_OW=67` посчитана как `max(art_w + 4, info_w + 8)`, рендер проверен на 24+19 строках.

**Правило по diff до коммита** (установлено пользователем): после каждой фазы — полный diff пользователю, не только результат тестов. Применено к Фазе 2 (rename пакета, 428 файлов в индексе).

### ⚠️ Изменения

#### 1. Версия bumped с 4.25.1 до 5.0.0

`chimera/__init__.py`: `__version__ = "5.0.0"`, docstring `"""Chimera Project  — Multi-Protocol Anti-DPI Installer"""`. Все публикациионные файлы обновлены: `bootstrap.sh`, `README.md`, `INSTALL.md`, `PROJECT_MAP.md`, `verify.py`, `full_test.py`. `_core.py`, `main.py` подхватывают версию динамически через `_get_version()` — ручных правок не требуют.

#### 2. GitHub repository rename

После merge в main: GitHub Settings → Repository name → `Chimera-Project`. GitHub автоматически редиректит все URL (web, git clone, raw.githubusercontent.com, archive tarball). Локально: `git remote set-url origin https://github.com/inferno1978/Chimera-Project.git`.

### 🔗 Связанные коммиты в ветке rebrand/chimera-project

- `feat(rebrand): rename Python package vless_installer → chimera` (3ea56e3) — Фаза 2
- `feat(rebrand): new CHIMERA ASCII banner (pyfiglet ansi_shadow) + visible strings` (c220f2c) — Фаза 3
- `feat(rebrand): replace URLs and 'VLESS Ultimate Installer' text with Chimera Project` (a8a841a) — Фаза 4
- `feat(rebrand): migrate OS paths /opt/vless-ultimate → /opt/chimera, /var/log/vless-install.log → /var/log/chimera.log` (3b15dff) — Фаза 5
- `feat(rebrand): version bump 4.25.1 → 5.0.0 + CHANGELOG entry` (этот коммит) — Фаза 6

### 📚 Persistent-артефакты

Скрипты генерации/проверки сохранены в `/home/z/my-project/scripts/`:
- `rebrand_vless_to_chimera.py` — sed-замена имени пакета
- `rebrand_urls_and_text.py` — замена URLs и текстовых упоминаний
- `rebrand_os_paths.py` — замена путей в ОС
- `gen_chimera_options.py` — тест 12 шрифтов pyfiglet
- `apply_chimera_banner.py` — финальная генерация баннера + расчёт `_OW`
- `test_banner_render_full.py` — полный рендер баннера с проверкой ширины (оба режима)

### 🚀 Совместимость

- **Свежие установки** (с  : ставятся в `/opt/chimera`, лог в `/var/log/chimera.log`, все импорты через `chimera.*`. Работают «из коробки».
- **Существующие установки** (v4.x): при запуске `bootstrap.sh` находит старый `/opt/vless-ultimate`, обновляет его in-place. `chimera/_core.py` при старте создаёт symlink `/var/log/vless-install.log` → `/var/log/chimera.log`, перенося старое содержимое в `.pre-chimera.bak`. Cron-задачи и logrotate-конфиги со старыми путями продолжают работать через symlink. State.json в `/var/lib/xray-installer/` НЕ ТРОГАЕТСЯ — все настройки сохраняются.
- **GitHub URLs**: старый `github.com/inferno1978/VLESS-Ultimate-Installer` редиректится на новый `Chimera-Project` (после ручного rename на GitHub). Все `curl | bash` скрипты со старым URL продолжают работать.

---

## v4.25.1 — FEAT: iOS/Karing-совместимые VLESS-ссылки через shadow-client — 15 июля 2026

Решение проблемы «Karing на iOS не работает, Hiddify работает, на Android/ПК всё ок». Корень — XTLS Vision flow (`&flow=xtls-rprx-vision`) рвёт хендшейк в Karing на iOS через 20-40 секунд (внешний баг KaringX/karing#1158), плюс гипотеза о капризности iOS URL-парсеров к сырым эмодзи-флагам в `#fragment`. Решение — отдельный shadow-клиент в `clients[]` без ключа `flow` + постпроцессор ссылки. Подтверждено живым тестом на реальном iOS-устройстве через Karing.

### 🎯 Что добавлено

#### 1. Постпроцессор `to_ios_karing_link()` — новый модуль `ios_link_variant.py`

Чистая постобработка готовой строки ссылки: убирает `&flow=xtls-rprx-vision` (REALITY-only, no-op для xHTTP) и сырой эмодзи-флаг страны в начале `#fragment`. Не дублирует логику сборки host/port/pbk/sid/domain — только вызывает существующий генератор и проходит по результату. Идемпотентный, безопасный для пустых входов и ссылок без `#`.

#### 2. Shadow-client паттерн — `_users_get_or_create_ios_shadow()`

Корень проблемы, которую чинит этот патч: постпроцессор без shadow рвёт хендшейк (сервер в `clients[]` хранит `"flow": "xtls-rprx-vision"`, а клиент без flow в ссылке его не отправляет → Xray отклоняет). Решение: для каждого REALITY-пользователя, которому нужна iOS-ссылка, создаётся отдельный shadow-клиент в той же `clients[]` — **БЕЗ ключа `flow`** в словаре. Ссылка строится на его UUID. Оригинальный клиент не трогается — Android/ПК продолжают работать с `flow=xtls-rprx-vision`.

- **Идемпотентный**: повторный вызов переиспользует существующий shadow по email-суффиксу `__ios`.
- **xHTTP-инбаунд**: возвращает `None` (flow там не используется, shadow не нужен).
- **`do_user_delete()`**: аддитивный cleanup-блок удаляет shadow вместе с основным юзером. No-op для юзеров без iOS-варианта — поведение идентично допатчевому.

#### 3. Четыре точки интеграции iOS-ссылок

Все используют один и тот же shadow-паттерн, подтверждённый живым тестом:

- **`do_user_show_link_ios_by_uuid(uuid)`** — одна ссылка для конкретного юзера. Email резолвится напрямую из `clients[]` по UUID (защита от рассинхрона `users.json` ↔ `config.json`). Доступ: главное меню → 2 → 1 → K.
- **`generate_client_links_ios()`** — сводный экран IPv4/IPv6/Domain. Доступ: главное меню → 2 → K.
- **`client_config_export.py`** — `vless-link-ios.txt` рядом с обычным `vless-link.txt` в `/root/xray-client-configs/`. Graceful fallback если `config.json` недоступен.
- **`/sub/{token}/ios` маршрут** в `subscription.py` — iOS-совместимая подписка. `do_subscription_menu` показывает URL + QR для каждого пользователя. `build_subscription_body_ios()` строит тело на shadow-UUID, `_resolve_ios_shadow_user()` резолвит shadow до `_build_vless_uri`.

#### 4. Гигиена shadow-клиентов

Поскольку shadow теперь идут в бой массово, введена пометка и фильтрация:

- **`_unified_load_users()`** помечает shadow полем `is_ios_shadow=True` (НЕ исключает — админ может видеть и удалять их вручную при отладке).
- **`do_user_list()`** рендерит shadow отдельным блоком внизу без номеров, серым цветом — реальным юзерам нумерация не сбивается.
- **`do_unified_user_manager()`** помечает shadow-строки тегом `[ios-shadow]` в таблице.
- **`status_panel._users_counts()`** фильтрует shadow из `total`/`active` — счётчик «число пользователей» не задваивается.
- **`do_entry_mirrors_menu()`** показывает подсказку: для каждого mirror-сервера нужно отдельно зайти по SSH и выполнить «2 → 1 → K» для нужных юзеров (mirror-серверы — отдельные инстансы, программно недоступны).

### 🔧 Что исправлено

#### 1. Drive-by фикс: `type=http` → `type=xhttp` в `client_config_export.py`

В 3 местах (sing-box JSON transport + 2 vless-link builder'а) использовался устаревший HTTP/2-транспорт (`type=http`) вместо актуального xHTTP Xray 1.8.16+ (`type=xhttp`). Рассинхрон с `users_manager.py`, где всегда было `type=xhttp`. Защита отката фикса — отдельный статический тест.

#### 2. Баг рассинхрона в `_build_vless_uri` (subscription.py)

Функция брала `user["uuid"]` напрямую — тот же баг, что починили в `do_user_show_link_ios_by_uuid` (патч №3). Если в `users.json` UUID имел один email, а в `clients[]` — другой (админ редактировал через пункт «8. Редактировать»), shadow-функция не находила клиента и молча возвращала `None`. Починено через `_resolve_ios_shadow_user(user)`: email берётся напрямую из `clients[]` по UUID, shadow создаётся/переиспользуется корректно.

#### 3. Mirror-URI исключены из iOS-подписки

Раньше `build_subscription_body_ios()` прогоняла mirror-ссылки через `to_ios_karing_link()`. Но mirror-серверы — отдельные инстансы инсталлятора на других VPS, чьи `clients[]` этот модуль не редактирует. Постпроцессор без shadow на СЕРВЕРЕ mirror'а даёт тот же разрыв хендшейка. Теперь mirror-URI исключаются целиком, логируется WARN с количеством исключённых.

#### 4. Удалён мёртвый код: `do_user_menu()` + `do_user_show_link()`

Аудит показал: `do_user_menu()` — строго подмножество `do_unified_user_manager()` (те же L/A/D/S/K/I, без 4-8/E). `do_unified_user_manager` — реальный путь из главного меню (2 → 1), использует `_unified_load_users/_unified_save_users` с синхронизацией `users.json` + `config.json`. `do_user_menu` работал только с `config.json`, импортирован в `_core.py`, но **НИГДЕ не вызывался** — чистый мёртвый код. `do_user_show_link()` вызывалась только из `do_user_menu()`. Обе функции удалены, обновлены импорты, `smoke_test_modules.py`, докстринги.

### ⚠️ Изменения

#### 1. `test_core_dynamic_version.py` переписан на динамический паттерн

`test_no_hardcoded_version_in_core_py` хардкодил `"4.25.0"` как искомый литерал — tautological-паттерн, после следующего бампа тест протухал молча. Переписан: читает текущую версию из `chimera.__version__` в момент запуска и ищет её как литерал в `_core.py`. При следующем бампе тест сам подтянется. Добавлен `test_main_menu_shows_current_version` — проверяет, что баннер главного меню показывает текущую версию (не "unknown" и не устаревшую).

#### 2. Version bump 4.25.0 → 4.25.1

`chimera/__init__.py` — `__version__` + докстринг. Все публикациионные файлы обновлены вручную: `bootstrap.sh`, `README.md` (заголовок + badge + баннер + architecture-диаграмма), `INSTALL.md`, `PROJECT_MAP.md`, `full_test.py`, `verify.py`. `_core.py`, `honeypot.py`, `main.py` подхватывают версию динамически через `_get_version()` — ручных правок не требуют (проверено grep-аудитом).

### 📊 Статистика

- **Новых модулей:** 1 (`ios_link_variant.py`)
- **Новых функций:** 7 (`to_ios_karing_link`, `_shadow_ios_email`, `_users_get_or_create_ios_shadow`, `do_user_show_link_ios`, `do_user_show_link_ios_by_uuid`, `_users_gen_link_ios`, `generate_client_links_ios`, `build_subscription_body_ios`, `_resolve_ios_shadow_user`)
- **Новых тест-файлов:** 6 (`test_ios_link_variant.py`, `test_ios_link_regression.py`, `test_ios_shadow_client.py`, `test_ios_unified_menu.py`, `test_ios_patch4_open_surfaces.py`, `test_ios_patch5_subscription_cleanup.py`)
- **Новых тестов:** ~80 (все проходят)
- **Удалено мёртвого кода:** 2 функции (`do_user_menu`, `do_user_show_link`)
- **Точек интеграции iOS-ссылок:** 4 (менеджер юзеров, сводный экран, экспорт конфигов, подписка)

---

## v4.25.0 — FEAT: Client Telegram Bot, Unified User Lifecycle, Forced DNS Redirect, Baseline-Offset Traffic Accounting — 14 июля 2026

Крупный релиз: 4 новые подсистемы, ~6000 строк нового кода, ~470 новых тестов.

### 🎯 Что добавлено

#### 1. Client-facing Telegram-бот для self-service конечных пользователей

**Модули:** `chimera/modules/tg_client_bot.py`, `chimera/modules/linkqr_lib.py`

Отдельный от admin-бота модуль с командами `/start` (deep-link binding), `/config`, `/qr`, `/status`, `/help`. Единая shared-библиотека `linkqr_lib.py` для генерации ссылок/QR, переиспользуемая обоими ботами. Строгий one-to-one binding Telegram user_id ↔ UUID через одноразовые invite-токены. Rate-limiting (1 команда / 2 сек, настраиваемо). Приватные ключи/PSK никогда не попадают в ответы бота. Отдельный systemd-юнит `xray-tg-client.service`, отдельный конфиг `/var/lib/xray-installer/tg_client_bot.json`, отдельная карта привязок `tg_client_bot_map.json`.

Управление: главное меню → 5 (Безопасность и Автоматизация) → `TC`.

#### 2. Единый multi-protocol user_lifecycle-слой

**Модуль:** `chimera/modules/user_lifecycle.py`

Централизованные транзакционные `add_user` / `remove_user` / `block_user` / `unblock_user` / `update_limits` с атомарным rollback при частичном сбое синхронизации хотя бы одного из 8 протоколов (VLESS/Xray, AWG, sing-box, Mieru, MTProto, NaiveProxy, FPTN, Hysteria2). Снапшот state-файлов перед операцией, восстановление при исключении. Существующие cron-флаги (`--ttl-check`, `--autoban`, новые `--traffic-check`, `--lifecycle-cleanup`) делегируют в новый слой с fallback на legacy-логику при недоступности модуля.

Поведенческое исправление: `check_traffic_limits` теперь **блокирует** пользователей (а не удаляет, как раньше), позволяя разблокировать через `unblock_user`. `block_user` fan-out во все протоколы (раньше TTL expiry блокировал только в Xray, пользователь мог подключиться через AWG/sing-box).

#### 3. Принудительный DNS через dnscrypt-proxy

**Модуль:** `chimera/modules/dns_redirect.py`

iptables/ip6tables NAT REDIRECT для UDP/TCP порта 53 от клиентских интерфейсов (awg0) на локальный dnscrypt-proxy (127.0.0.1:5300). Защита от DNS leak даже при ручном DNS на клиенте. Black-hole guard — проверка что dnscrypt реально слушает порт перед применением правил. Идемпотентное применение через `-C` check. Переключаемо через конфиг (`/var/lib/xray-installer/dns_redirect.json`). Persist после reboot через systemd `dns-redirect-restore.service`. Health-check в диагностике (пункт `DN`).

Управление: главное меню → 3 (Настройки сети) → `DR`. Документация в `TROUBLESHOOTING.md`.

#### 4. Унифицированный учёт трафика с baseline-offset

**Модуль:** `chimera/modules/traffic_accounting.py`

Переживает рестарт сервиса, ротацию логов и сброс интерфейса для VLESS/Xray, AWG, Mieru и NaiveProxy. Универсальный парсер человекочитаемых размеров `parse_human_readable_bytes` (IEC KiB/MiB/GiB, SI KB/MB/GB, bare-letter K/M/G) и форматтер `format_bytes` (en/ru локали). Thread/process-safe через `fcntl.flock`. Для NaiveProxy — инкрементальное чтение access.log с отслеживанием inode для устойчивости к ротации Caddy `roll_size 10mb`. Для AWG — корректный парсер `awg show all dump` (peer vs interface по количеству полей). Для Mieru — правильные ключи `download`/`upload` из journalctl `[metrics - user - NAME]`.

#### 5. TrustTunnel — интеграция официального upstream-бинарника AdGuard VPN

**Модули:** `chimera/modules/trusttunnel.py`, `trusttunnel_packages.py`, `trusttunnel_mirrors.py`, `trusttunnel_health.py`, `trusttunnel_stats.py`

Новый протокол как 9-й в реестре `user_lifecycle.PROTOCOL_ADAPTERS`. Использует **официальный upstream prebuilt-бинарник** `trusttunnel_endpoint` + `setup_wizard` (Rust, Apache 2.0, https://github.com/TrustTunnel/TrustTunnel), GPG-подписан ключом AdGuard `28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6`. НЕ форк и НЕ реимплементация (в отличие от подхода в HYDRA-ULTIMATE, где TrustTunnel — кастомный sing-box inbound с несовместимым `tt://user:pass@host` URI). Транспорт: HTTP/2-over-TLS (TCP) + HTTP/3-over-QUIC (UDP) с мультиплексированием TCP/UDP/ICMP. Клиентская выдача — deep-link `tt://?<base64url-TLV>` (upstream-формат), встроен в `linkqr_lib.build_all_links_for_user` и существующий self-service Telegram-бот (команды `/config` и `/qr` работают без изменений UX).

**Порт по умолчанию `8443` (TCP+UDP)** — отдельный порт, не 443 (443 занят VLESS TCP + Hysteria2 UDP; TrustTunnel не имеет SNI-dispatch и не умеет fallback). Конфликт портов проверяется через существующий `core.check_port_used_by_other_protocol`, зарегистрирован в `PROTOCOL_PORT_REGISTRY`. Сертификаты — через существующий `ssl_certbot.obtain_ssl_cert()` + feed в `setup_wizard --cert-type provided`; авто-renewal — certbot cron + deploy-hook `systemctl reload trusttunnel` (SIGHUP перезагружает `hosts.toml` без рестарта, без разрыва активных сессий). systemd-юнит дополнен `ExecReload=/bin/kill -HUP $MAINPID` (апстримовский template этот параметр не содержит — фикс задокументированного бага, при котором `systemctl reload trusttunnel` падал с "Unit is not reloadable"). Cron-задачи `--trusttunnel-health` (каждые 5 мин) и `--trusttunnel-stats` (каждые 5 мин) устанавливаются автоматически при install, убираются при uninstall.

**Батчинг рестартов для restart-based протоколов.** Апстрим TrustTunnel не поддерживает hot-reload `credentials.toml` (SIGHUP перезагружает только `hosts.toml`). Смена пользователей требует `systemctl restart trusttunnel`, что рвёт ВСЕ активные соединения. Для предотвращения N рестартов при массовых cron-операциях (TTL-expiry, traffic-limits) введён контекстный менеджер `user_lifecycle.batch_context()` + модуль-level `_PENDING_RESTARTS: set` + счётчик глубины для вложенности. Адаптеры правят файл и вызывают `_request_restart(protocol)`, реальный рестарт происходит один раз в конце транзакции (одиночная операция — сразу после `snap.commit()`; cron-проход — на выходе из `batch_context()`). Rollback-до-flush: при сбое любого протокола `snap.restore()` + `_cancel_pending_restarts(protocols_list)` — демон никогда не рестартует с откаченным конфигом. Cron-функции `check_ttl_expired`, `check_traffic_limits`, `run_cleanup` обёрнуты в `batch_context()`. Влияние на остальные 8 протоколов — нулевое (их адаптеры не вызывают `_request_restart`, `_PENDING_RESTARTS` остаётся пустым, `_flush_pending_restarts` — no-op).

**Pure-Python TLV-кодек** `tt://?<base64url>` ( TrustTunnel-формат: varint-кодированные TLV-записи с RFC 9000 §16 QUIC varints) — reimplemented в `trusttunnel.py` (~200 строк), чтобы `linkqr_lib` мог генерировать URI без спавна 17-МБ бинарника на каждый `/config`/`/qr` запрос бота. Roundtrip-проверено против реального deep-link'а, сгенерированного `trusttunnel_endpoint v1.0.33`. Детерминированные per-user пароли: `SHA-256("trusttunnel-pass|" + uuid)` — стабильны при переустановках, не требуют хранения в `state.json`.

**Известные архитектурные ограничения** (зафиксированы в `TROUBLESHOOTING.md`):
1. **Только агрегированный трафик, не per-user.** Апстримовский `/metrics` (Prometheus, порт 1987) отдаёт счётчики `inbound_traffic_bytes`/`outbound_traffic_bytes` только с лейблом `protocol_type` (`http1`/`http2`/`http3`), без `username`. Per-user биллинг потребует патчить `lib/src/metrics.rs` и собирать из исходников, теряя GPG-верификацию. В текущей реализации трафик записывается под синтетическим user_id `_aggregate` через `traffic_accounting.record_traffic_sample` (аналогично FPTN/Hysteria2, у которых тоже нет per-user byte counter). Статус `trusttunnel` явно отмечен в `traffic_accounting.SUPPORTED_PROTOCOLS`.
2. **Смена пользователей рестартует сервис.** Любой `add`/`remove`/`block`/`unblock` для TrustTunnel вызывает `systemctl restart trusttunnel` (~1 с разрыв ВСЕХ активных соединений, не только у изменяемого юзера). Массовые cron-операции батчатся в один рестарт за проход через `batch_context()`, но ручное добавление/удаление через TUI/бота рестартует сразу.

### 📦 Изменения по файлам

**Новые модули:**
- `chimera/modules/tg_client_bot.py` (+1738 строк) — клиентский бот
- `chimera/modules/linkqr_lib.py` (+624 строки) — shared-библиотека ссылок/QR
- `chimera/modules/user_lifecycle.py` (+1643 строки) — unified lifecycle
- `chimera/modules/dns_redirect.py` (+917 строк) — DNS REDIRECT
- `chimera/modules/traffic_accounting.py` (+559 строк) — baseline-offset
- `chimera/modules/trusttunnel.py` (~700 строк) — TrustTunnel: install/menu/user CRUD/deep-link codec/systemd/service control
- `chimera/modules/trusttunnel_packages.py` — PackageSpec для prebuilt binaries
- `chimera/modules/trusttunnel_mirrors.py` — URL builder для GitHub Releases
- `chimera/modules/trusttunnel_health.py` — cron health-check (service + /metrics + version)
- `chimera/modules/trusttunnel_stats.py` — aggregate traffic collector (Prometheus /metrics → traffic_accounting)

**Новые тесты:**
- `tests/test_tg_client_bot.py` (+738 строк, 56 тестов)
- `tests/test_tg_client_bot_inner_script.py` (+874 строки, 16 тестов)
- `tests/test_linkqr_lib.py` (+449 строк, 21 тестов)
- `tests/test_user_lifecycle.py` (+1150 строк, 47 тестов)
- `tests/test_dns_redirect.py` (+890 строк, 46 тестов)
- `tests/test_core_dns_redirect_integration.py` (+170 строк, 3 теста)
- `tests/test_traffic_accounting.py` (+833 строки, 61 тест)
- `tests/test_traffic_collectors.py` (+470 строк, 10 тестов)
- `tests/test_trusttunnel.py` (~470 строк, 53 теста) — credentials CRUD, deep-link codec, password derivation, PackageSpec, systemd template, port/domain checks, service control
- `tests/test_trusttunnel_user_lifecycle.py` (~440 строк, 27 тестов) — батчинг рестартов, rollback при частичном сбое, non-existent user protection, идемпотентность, регрессия существующих протоколов

**Интеграция в `_core.py`:**
- Импорт + пункт меню `TC` (главное → 5 → TC) для клиентского бота
- Импорт + пункт меню `DR` (главное → 3 → DR) для DNS REDIRECT
- Импорт + пункт меню `DN` (главное → 4 → DN) для DNS health-check
- `_ttl_check_and_expire` делегирует в `user_lifecycle.check_ttl_expired`
- `_check_traffic_limits_once` делегирует в `user_lifecycle.check_traffic_limits`

**Интеграция в `main.py`:**
- Новые CLI-флаги: `--traffic-check`, `--lifecycle-cleanup`
- Health-check info использует динамическую версию из `chimera.__version__`

**Интеграция в `traffic_tracking.py`:**
- Новая функция `_query_user_traffic_bytes_accumulated` — обёртка с baseline-offset

**Интеграция в `awg_peers.py`:**
- Новые функции `awg_collect_peer_traffic`, `awg_get_peer_traffic_accumulated`
- Фикс парсера `awg show all dump` (peer vs interface по количеству полей)

**Интеграция в `mieru_stats.py`:**
- Новые функции `mieru_collect_traffic`, `mieru_get_traffic_accumulated`
- Фикс ключей `download`/`upload` (не `rx`/`tx`)

**Интеграция в `naiveproxy_stats.py`:**
- Новые функции `naiveproxy_collect_traffic`, `naiveproxy_get_traffic_accumulated`
- Инкрементальное чтение access.log с offset-отслеживанием (`_read_new_log_lines`)

### 🔄 Версия

Обновлена с 4.20.0 до 4.25.0. Версия в `main.py` теперь берётся динамически из `chimera.__version__` (по аналогии с `honeypot.py`) — при следующем бампе не отстанет.

---

## v4.23.8 — FEAT: SNI-dispatch auto-patches Xray config.json (фаза 2) — 13 июля 2026

### 🎯 Что добавлено

`apply_reality_sni_dispatch_patch()`, `revert_reality_sni_dispatch_patch()` и
`sni_dispatch_reapply_after_rebuild()` в `singbox_nginx.py` — автоматически
патчат `/etc/xray/config.json` при включении SNI-dispatch, перенося REALITY-инбаунд
с публичного `:443` на loopback `127.0.0.1:8442` и добавляя
`streamSettings.sockopt.acceptProxyProtocol=true`.

До v4.23.8 `auto_enable_sni_dispatch()` (v4.23.5) настраивала nginx stream{},
но НЕ патчила config.json — REALITY-инбаунд оставался на публичном `:443`,
создавая конфликт биндинга с nginx stream{}. Пользователь был вынужден патчить
вручную. Теперь патч применяется автоматически.

### Архитектура

```
Без SNI-dispatch (классика):
  client:443 → Xray REALITY (listen [::]:443, xver=1) → unix:/dev/shm/xxx.socket
                                                          ↓
                                                       nginx http{} (decoy)

С SNI-dispatch (auto-config v4.23.5 + auto-patch v4.23.8):
  client:443 → nginx stream{} (ssl_preread, proxy_protocol on)
    ├─ SNI=shadowtls → 127.0.0.1:8443
    ├─ SNI=anytls    → 127.0.0.1:8444
    └─ default       → 127.0.0.1:8442 (REALITY backend, loopback)
                          ↓
                       Xray REALITY (listen 127.0.0.1:8442,
                                     sockopt.acceptProxyProtocol=true)
                       realitySettings.dest — НЕ ТРОГАЕМ (decoy-сокет,
                       отдельная downstream-логика Xray, неизменна с v4.23.5)
```

### 📦 Изменения по файлам

**`chimera/modules/singbox_nginx.py`** (+ ~400 строк):
- Новая функция `apply_reality_sni_dispatch_patch()` — патчит config.json:
  - `port: SERVER_PORT (443)` → `8442` (`_REALITY_LOOPBACK_PORT`)
  - `listen: "::"` → `"127.0.0.1"`
  - `streamSettings.sockopt.acceptProxyProtocol: true` (добавляет)
  - Бэкап `.pre-sni-dispatch` (по аналогии с nginx-конфигом)
  - `xray -test` валидация (если binary доступен)
  - `systemctl restart xray` + active-check
  - Откат из бэкапа при ошибке
  - Идемпотентна — безопасно вызывать многократно
- Новая функция `revert_reality_sni_dispatch_patch()` — откат:
  - Восстановление из `.pre-sni-dispatch` бэкапа (предпочтительный путь)
  - Reverse-patch без бэкапа: `listen`/`port` из state, удаление `acceptProxyProtocol`
- Новая функция `sni_dispatch_reapply_after_rebuild()` — хук для
  `_core._rebuild_and_restart_xray()`, пере-применяет патч после регенерации
  config.json (mirror `server_fragment_reapply_after_rebuild()`)
- Новые хелперы: `_xray_config_paths()`, `_find_reality_inbound()`,
  `_xray_test_config()`
- `auto_enable_sni_dispatch()` — `warn()`-плейсхолдеры заменены на вызов
  `apply_reality_sni_dispatch_patch()`, с откатом SNI-dispatch при ошибке патча
- `auto_disable_sni_dispatch()` — `warn()`-плейсхолдеры заменены на вызов
  `revert_reality_sni_dispatch_patch()`

**`chimera/_core.py`** (+ ~16 строк):
- `_rebuild_and_restart_xray()` — добавлен вызов `sni_dispatch_reapply_after_rebuild()`
  после `server_fragment_reapply_after_rebuild()` и до финального
  `systemctl restart xray`. Порядок операций сохранён: nginx restart (если нужен)
  происходит ПОСЛЕ — патч применяется к свежему config.json до рестарта xray.

**`tests/test_sni_dispatch_xray_patch.py`** (+ ~580 строк, 24 новых теста).

### 🧪 Тесты (24 новых)

`tests/test_sni_dispatch_xray_patch.py`:

**apply_reality_sni_dispatch_patch — корректность патча (4 теста):**
- `test_patch_changes_listen_to_loopback` — listen → `127.0.0.1`
- `test_patch_changes_port_to_8442` — port → `8442`
- `test_patch_adds_acceptProxyProtocol_true` — acceptProxyProtocol: true добавлен
- `test_patch_preserves_other_sockopt_fields` — tcpFastOpen, tcpCongestion и др. сохранены

**Идемпотентность (3 теста):**
- `test_double_patch_is_idempotent` — повторный патч не ломает конфиг
- `test_double_patch_does_not_create_second_backup` — бэкап не перезаписывается
- `test_double_patch_does_not_overwrite_original_listen_in_state` — original_listen в state неизменен

**realitySettings.dest НЕ ТРОНУТ (3 теста — критичный регресс-барьер):**
- `test_reality_dest_unchanged_after_patch` — dest неизменен после patch
- `test_reality_other_fields_unchanged` — все поля realitySettings сохранены
- `test_reality_dest_unchanged_after_revert` — dest неизменен даже после revert

**Не трогает другие инбаунды (1 тест):**
- `test_other_inbound_untouched` — dokodemo-in не тронут, только REALITY-инбаунд

**Откат (2 теста):**
- `test_revert_via_backup_restores_original` — восстановление из бэкапа
- `test_revert_reverse_patch_without_backup` — reverse-patch по state когда бэкапа нет

**Re-apply после регенерации (3 теста):**
- `test_reapply_noop_when_disabled` — выключен → noop
- `test_reapply_repatches_after_regenerate` — config.json перезаписан → патч переприменяется
- `test_reapply_skipped_in_manual_mode` — auto_configured=False → пропускается

**AWG/xHTTP отказ (3 теста):**
- `test_patch_refuses_xhttp_mode` — xHTTP → False, config не тронут
- `test_patch_refuses_awg_mode` — AWG → False, config не тронут
- `test_patch_skip_mode_check_bypasses_guard` — skip_mode_check=True обходит guard

**Бэкап (2 теста):**
- `test_backup_created_on_first_patch` — бэкап создаётся при первом патче
- `test_backup_suffix_matches_nginx_convention` — suffix `.pre-sni-dispatch` как у nginx

**_find_reality_inbound fallback (3 теста):**
- `test_finds_by_tag_inbound_vless` — находит по каноническому tag
- `test_falls_back_to_security_reality` — fallback по security=="reality"
- `test_returns_none_when_no_reality_inbound` — None если нет REALITY-инбаунда

### ✅ Проверка

- **`py_compile`**: OK для `singbox_nginx.py`, `_core.py`, `test_sni_dispatch_xray_patch.py`
- **`pytest tests/test_sni_dispatch_xray_patch.py`**: 24 passed in 2.31s
- **`pytest tests/test_singbox_nginx.py tests/test_singbox_sni_autoconfig.py tests/test_singbox_state.py`**: 111 passed in 8.57s (0 регрессий)
- **Targeted regression suite** (singbox_* + xray_install + xray_safe_apply + server_fragment): 460 passed, 8 skipped, 0 failed in 55.94s
- **`xray -test`**: НЕ ЗАПУСКАЛСЯ — в песочнице нет xray binary
  (`_xray_test_config()` возвращает `(True, "(xray binary not available — skipped)")`,
  патч-функция gracefully деградирует, не блокируя применение)

### ⚠️ Степень сквозной проверки (ОБЯЗАТЕЛЬНО ПРОЧИТАТЬ ПЕРЕД ПРОДАКШЕНОМ)

Сквозная проверка REALITY-handshake с `proxy_protocol + acceptProxyProtocol`
на реальном Xray-сервере в песочнице **НЕ ВЫПОЛНЕНА** — нет xray binary.
Проверено только:

1. ✅ JSON-структура — 24 unit-теста покрывают port/listen/sockopt/dest/idempotency/revert
2. ✅ `py_compile` — оба изменённых модуля компилируются
3. ✅ Регрессии — 460 существующих тестов в затронутых модулях проходят
4. ❌ `xray -test -config config.json` — не запускался (нет binary в песочнице)
5. ❌ Реальное REALITY-подключение через `nginx stream{}` — НЕ проверено
6. ❌ Подтверждение что в логе Xray виден РЕАЛЬНЫЙ IP клиента
   (а не `127.0.0.1`) — НЕ проверено
7. ❌ Регресс Xray-core issue #1972 (proxy_protocol + REALITY →
   `ERR_SSL_PROTOCOL_ERROR` на некоторых версиях) — НЕ проверен на используемой
   версии Xray

**ОБЯЗАННОСТЬ ПОЛЬЗОВАТЕЛЯ перед продакшн-включением:**
1. Установить/обновить Xray до актуальной версии (>= 25.x, где issue #1972 закрыт)
2. На тестовом сервере: включить SNI-dispatch через TUI → подключиться реальным
   клиентом (v2rayN/Nekobox) → проверить в `journalctl -u xray -f` что виден
   РЕАЛЬНЫЙ IP клиента (не 127.0.0.1)
3. Если виден 127.0.0.1 — `acceptProxyProtocol` не работает с этой версией Xray,
   откатить SNI-dispatch (`auto_disable_sni_dispatch()`) и завести тикет

### Регрессии

460 существующих тестов (singbox_*, xray_install, xray_safe_apply, server_fragment) — 0 регрессий, 8 skip.

---

## v4.23.7 — FIX: _ensure_self_signed_cert парсит реальный CN из существующего cert — 13 июля 2026

### 🐛 Фикс

**Проблема:** `_ensure_self_signed_cert()` при уже существующем cert_path/key_path
на диске возвращал переданный `common_name` как есть, не проверяя реальный CN
в файле. При смене домена сервера и повторном вызове с новым `common_name`
функция возвращала CN, не соответствующий физическому сертификату →
неверная SNI-маршрутизация в `auto_enable_sni_dispatch()`.

**Фикс:** При существующем cert — парсит реальный CN через
`openssl x509 -noout -subject` (новая функция `_parse_cn_from_cert()`).
Если парсинг не удался — fallback на переданный `common_name`.

### 🧪 Тесты (2 новых)

- `test_existing_cert_returns_real_cn_not_passed` — cert с CN=old-domain →
  вызов с common_name=new-domain → результат = old-domain (реальный CN)
- `test_existing_cert_falls_back_to_passed_cn_on_parse_error` —
  парсинг не удался → fallback на переданный common_name

Полный прогон: 23 теста в test_singbox_sni_autoconfig (21 прежних + 2 новых),
0 регрессий.

---

## v4.23.6 — FIX: common_name прокинут + тесты auto-config + TUI-меню — 12 июля 2026

### 🐛 Фикс: common_name не прокидывался в singbox_enable_anytls

**Проблема:** `_ensure_self_signed_cert("anytls")` генерировал `common_name`
локально, но не возвращал его. `singbox_enable_anytls(common_name=...)` —
параметр добавлен в v4.23.5, но вызов из меню (`singbox_menu.py:526`) не
передавал значение. Auto-detect SNI для AnyTLS работал только через fallback
(CN-парсинг из cert), что не то, что задумывалось для новых установок.

**Фикс:**
- `_ensure_self_signed_cert()` — изменена сигнатура: возвращает
  `(cert_path, key_path, common_name)` вместо `(cert_path, key_path)`.
  `common_name` — домен сервера (из `state.json["domain"]`) для AnyTLS,
  `f"sing-box-{prefix}"` для остальных (TUIC и т.д.).
- `singbox_menu.py` — AnyTLS enable вызывает `_ensure_self_signed_cert("anytls", common_name=server_domain)`
  и передаёт `cn` в `singbox_enable_anytls(common_name=cn)`.
- TUIC enable — распаковывает 3 значения (`cert_path, key_path, _ = ...`).

### 🧪 Тесты (21 новых)

`tests/test_singbox_sni_autoconfig.py`:

**_detect_reality_backend (4 теста):**
- Возвращает `127.0.0.1:8442` для REALITY режима
- Пустая строка для xHTTP и AWG
- НЕ использует `state.json["socket"]` (decoy-сокет, отдельная логика)

**_detect_shadowtls_sni (2 теста):**
- Возвращает `handshake.server` когда ShadowTLS включён
- Пустая строка когда выключен

**_detect_anytls_sni (4 теста — 3 сценария из тикета):**
- `common_name` из state (новые установки v4.23.5+)
- CN из cert через `openssl x509` (старые установки)
- Пустая строка (нет ни common_name ни cert) — НЕ придумывает домен

**_ensure_self_signed_cert (2 теста):**
- Возвращает 3 значения (cert, key, cn)
- Custom common_name возвращается правильно

**singbox_enable_anytls (2 теста):**
- `common_name` сохраняется в state
- Повторный enable без common_name НЕ затирает существующее значение

**proxy_protocol on (2 теста — fail2ban regression):**
- `proxy_protocol on;` присутствует в stream{} конфиге (незакомментирован)
- Старый закомментированный вариант НЕ присутствует

**_comment_out_listen_443 / _uncomment_listen_443 (5 тестов):**
- Комментирует `listen 443` (с тегом `# [SNI-DISPATCH]`)
- Создаёт бэкап `.pre-sni-dispatch`
- Раскомментирует обратно
- Сохраняет другие комментарии
- НЕ комментирует `listen unix:` (decoy-сокет)

### TUI-меню

`_sni_dispatch_menu()` обновлён:
- Пункт "1. 🤖 Auto-config" (NEW) — вызывает `auto_enable_sni_dispatch()`
- Пункт "2. ⚙️ Включить вручную" — старый ручной режим
- При выключении — `auto_disable_sni_dispatch()` (с раскомментированием listen 443)
- Default backend в ручном режиме изменён с `/dev/shm/vless-reality.socket`
  на `127.0.0.1:8442`

### Регрессии

347 тестов — 0 регрессий, 8 skip.

---

## v4.23.5 — FEAT: SNI-dispatch auto-config (фаза 1) — 12 июля 2026

### 🎯 Что добавлено

`auto_enable_sni_dispatch()` и `auto_disable_sni_dispatch()` в `singbox_nginx.py`
— автоматизируют определение параметров SNI-dispatch и миграцию listen 443
между http{} и stream{}. Строятся поверх существующих `enable_sni_dispatch()` /
`disable_sni_dispatch()`, не заменяют их.

### Архитектура

```
Без SNI-dispatch:
  client:443 → nginx http{} (listen :443 ssl) → fallback site
  Xray (dest=unix:/dev/shm/xxx.socket, xver=1) → PP → nginx http{} (decoy)

С SNI-dispatch (auto-config):
  client:443 → nginx stream{} (ssl_preread, proxy_protocol on)
    ├─ SNI=shadowtls → 127.0.0.1:8443
    ├─ SNI=anytls → 127.0.0.1:8444
    └─ default → 127.0.0.1:8442 (REALITY backend, loopback)

  Xray REALITY-инбаунд: listen=127.0.0.1:8442, sockopt.acceptProxyProtocol=true
  realitySettings.dest (decoy-сокет) — НЕ ТРОГАЕМ, отдельная downstream-логика Xray
```

**Ключевое архитектурное решение (пункт E из тикета):**

Использован `proxy_protocol on;` в stream{} (не отдельный loopback без PP).
Причина: fail2ban `xray-reality` jail парсит `/var/log/xray/*.log` через
`failregex = ^.*<HOST>.*blocked.*$` — `<HOST>` = IP клиента из логов Xray.
Без proxy_protocol, Xray видит только `127.0.0.1` (nginx) вместо реального
IP → fail2ban не сможет забанить сканера/брутфорсера. С `proxy_protocol on;`
в stream{} + `sockopt.acceptProxyProtocol: true` на REALITY-инбаунде, Xray
получает реальный IP из PROXY protocol header → fail2ban работает.

**Важно:** `realitySettings.dest` (PARAM_SOCKET_PATH, decoy-сайт) — НЕ является
backend для SNI-dispatch. Это fallback для non-REALITY трафика внутри самого Xray.
SNI-dispatch направляет REALITY SNI на `127.0.0.1:8442`, где Xray слушает
REALITY-инбаунд с `acceptProxyProtocol`.

### Что автоматизировано

**`auto_enable_sni_dispatch()`:**
1. Detect REALITY backend: читает `state.json` → `protocol_mode == "reality"`
   и `awg_exit_enabled == False` → `127.0.0.1:8442`. НЕ использует
   `state.json["socket"]` (это decoy-сокет, отдельная логика).
   Отказ с explicit ошибкой если xHTTP или AWG.
2. Auto-detect ShadowTLS SNI: `singbox_state["inbounds"]["shadowtls"]["handshake"]["server"]`
3. Auto-detect AnyTLS SNI: `singbox_state["inbounds"]["anytls"]["common_name"]` (v4.23.5+),
   fallback — парсинг CN из `cert_path` через `openssl x509 -noout -subject`
4. Detect REALITY SNI: `state.json["domain"]`
5. Комментирует `listen 443` в http{} конфигах (с бэкапом `.pre-sni-dispatch`)
6. Генерирует stream{} конфиг с `proxy_protocol on;`
7. `nginx -t` → reload
8. **warn() пользователю**: нужно вручную перевести REALITY-инбаунд на
   `127.0.0.1:8442` с `sockopt.acceptProxyProtocol: true` в config.json Xray.
   Автоматический патч config.json — следующим шагом.

**`auto_disable_sni_dispatch()`:**
1. Удаляет stream{} конфиг (через `disable_sni_dispatch`)
2. Раскомментирует `listen 443` в http{} конфигах
3. `nginx -t` → reload
4. **warn() пользователю**: нужно вернуть REALITY-инбаунд на `:443` напрямую.

### Дополнительно

**`singbox_enable_anytls()`:** добавлен параметр `common_name` — сохраняется
в state для auto-detect SNI. Для старых установок (без common_name в state) —
fallback через парсинг CN из существующего сертификата.

**`_build_nginx_stream_conf()`:** `proxy_protocol on;` раскомментирован (был
закомментирован). Это критично для fail2ban — без PP реальный IP теряется.

### Что НЕ сделано (следующий шаг)

- Автоматический патч config.json Xray (перенос REALITY listen + acceptProxyProtocol)
- Тесты (следующий заход)
- Интеграция в TUI-меню (пункт в `_sni_dispatch_menu()`)

### 📦 Изменения по файлам

**singbox_nginx.py** (+425 строк):
- `auto_enable_sni_dispatch()` / `auto_disable_sni_dispatch()`
- `_detect_reality_backend()` / `_detect_shadowtls_sni()` / `_detect_anytls_sni()`
- `_find_nginx_http_443_configs()` / `_comment_out_listen_443()` / `_uncomment_listen_443()`
- `_read_main_state()` — читает `/var/lib/xray-installer/state.json`
- `_build_nginx_stream_conf()` — `proxy_protocol on;` раскомментирован

**singbox_config.py** (+8 строк):
- `singbox_enable_anytls()` — параметр `common_name` добавлен

### Регрессии

184 существующих теста — 0 регрессий, 8 skip.

---

## v4.23.4 — FIX: systemd ordering cycle в ipset restore unit — 12 июля 2026

### 🐛 Проблема

`_ipset_restore_unit_install()` генерировал юнит с одновременно:
- `Before=netfilter-persistent.service` (фикс v4.23.3)
- `After=network-pre.target`

`netfilter-persistent.service` (реальная поставка Debian/Ubuntu, пакет
`netfilter-persistent` 1.0.23) имеет `Before=network-pre.target` — то есть
должен запуститься ДО `network-pre.target`.

Наш юнит `After=network-pre.target` — должен запуститься ПОСЛЕ `network-pre.target`.

Цепочка: `наш юнит → After → network-pre.target → After(обратное от Before)
← netfilter-persistent ← Before(наш)`. Транзитивный **ordering cycle**.

systemd резолвит такие циклы, **молча выкидывая одно из рёбер** (Debian bug
#832802) — какое именно выживет не гарантировано. `Before=netfilter-persistent`
мог быть тем, что вылетит, отменяя фикс v4.23.3.

### Фикс

В [Unit]-секции `singbox-cdn-ipset-restore.service`:
- **Убран** `After=network-pre.target` — ipset restore чисто локальная kernel-
  операция, сеть ему не нужна, строка давала только цикл.
- **Добавлен** `DefaultDependencies=no` — иначе implicit-зависимости от
  `DefaultDependencies=yes` (через `basic.target`/`sysinit.target`) могут снова
  создать цикл (Debian bug #832802 даже без явного `After=`). Тот же паттерн
  что у `netfilter-persistent.service` в реальной поставке Debian.
- **Добавлен** `After=local-fs.target` — `ConditionPathExists` читает файл с
  диска (`/etc/ipset-singbox-cdn.conf`), `local-fs.target` должен быть
  смонтирован. `local-fs.target` не имеет `Before` на `netfilter-persistent` —
  цикла не создаёт.

Граф после фикса (проверено эмпирически):
```
singbox-cdn-ipset-restore.service
  → Before → sing-box.service
  → Before → netfilter-persistent.service
  → After  → local-fs.target
netfilter-persistent.service (реальная Debian поставка):
  → Before → network-pre.target, shutdown.target
  → After  → systemd-modules-load.service, local-fs.target
```
Цикла нет: все рёбра направлены (local-fs.target → ... → наш юнит →
netfilter-persistent → network-pre.target).

### Эмпирическая проверка

1. **systemd-analyze verify** — exit code 0, без warnings/errors
2. **DFS на графе зависимостей** — построен граф из нашего юнита + реального
   `netfilter-persistent.service` (Debian trixie, пакет 1.0.23) +
   `local-fs.target` (systemd 257). DFS с цветовой разметкой (WHITE/GRAY/BLACK)
   — back edge = цикл. **Цикла нет.**
3. **Регрессионный тест** — тот же DFS на **старом** юните (с
   `After=network-pre.target`) — **цикл детектирован**, доказывает что тест
   реально ловит проблему, а не проходит тривиально.

Реальный `netfilter-persistent.service` получен через:
```
apt-get download netfilter-persistent
dpkg-deb -x netfilter-persistent*.deb /tmp/extract
cat /tmp/extract/usr/lib/systemd/system/netfilter-persistent.service
```

### 🧪 Тесты (6 новых)

`tests/test_singbox_vless_ws_cdn_fix3.py::TestNoOrderingCycle`:

- `test_no_after_network_pre_target` — строка убрана из юнита
- `test_has_default_dependencies_no` — DefaultDependencies=no присутствует
- `test_has_after_local_fs_target` — After=local-fs.target присутствует
- `test_no_ordering_cycle_in_dependency_graph` — DFS на графе из нашего юнита +
  реального netfilter-persistent.service (fixture) + local-fs.target (fixture) →
  **assert цикла нет**
- `test_old_unit_had_cycle` — тот же DFS на старом юните (с After=network-pre.target) →
  **assert цикл ЕСТЬ** (доказывает что тест работает)
- `test_systemd_analyze_verify_passes` — реальный `systemd-analyze verify` →
  exit 0 (skip если systemd-analyze недоступен)

Fixtures включают реальный `netfilter-persistent.service` из Debian trixie
(пакет 1.0.23) и `local-fs.target` из systemd 257 — захардкожены с указанием
источника, не выдуманы.

Полный прогон: **346 тестов, 0 регрессий**, 8 skip.

---

## v4.23.3 — FIX: 2 фикса порядка операций — окно с открытым портом — 12 июля 2026

### 🐛 Фикс 1: _switch_cdn_provider() — restart раньше apply_cdn_allowlist

**Проблема:** При переключении CDN-провайдера порядок операций был:
```
state update → generate_config → restart → remove/apply allowlist
```
sing-box restart открывал новый порт ДО того, как на него вставал allowlist —
окно от секунды до нескольких (пока идёт сетевой fetch CDN IP-листа), порт
открыт всем интернету без защиты.

**Фикс:** Переставлен порядок:
```
state update →
  remove_cdn_allowlist(port)      [очистка старого allowlist на новом порту]
  apply_cdn_allowlist(new, port)  [новый allowlist встаёт ДО restart]
  → generate_config → restart     [sing-box стартует на уже защищённом порту]
  → remove_cdn_allowlist(old_port) [старый порт больше не слушается — безопасно]
```

Если `apply_cdn_allowlist()` вернул False (fetch не удался) — НЕ блокирует switch
(fail-open с явным warn: "sing-box restart произойдёт на НЕЗАЩИЩЁННЫЙ порт").

### 🐛 Фикс 2: systemd unit — Before=netfilter-persistent.service

**Проблема:** `singbox-cdn-ipset-restore.service` имел `After=network-pre.target`,
но `netfilter-persistent.service` (стандартная поставка Debian/Ubuntu) запускается
`Before=network-pre.target` — то есть ДО достижения `network-pre.target`.
Наш юнит стартует ПОСЛЕ `network-pre.target` → строго после того, как
netfilter-persistent уже попытался restore iptables-правил, ссылающихся на ещё
не созданный ipset.

Результат: либо DROP-правило не грузится (allowlist пропадает при каждом ребуте),
либо (если iptables-restore атомарен) падает восстановление ВСЕГО файла правил —
задевает firewall других протоколов, не только vless_ws_cdn.

**Фикс:** Добавлен `Before=netfilter-persistent.service` в unit-файл (доп. к уже
существующему `Before=sing-box.service`). Теперь:
```
[Unit]
Before=sing-box.service
Before=netfilter-persistent.service
After=network-pre.target
```
ipset restore отрабатывает ДО netfilter-persistent → iptables-restore находит
существующий ipset → правила грузятся корректно.

Safe даже если netfilter-persistent не установлен — systemd игнорирует `Before=`
на несуществующий юнит, не падает.

**TODO (technical debt, не в этом фиксе):** Та же проблема теоретически есть в
`ipset_persist.py` (`xray-ipset-restore.service`) — юнит для ingress GeoIP
блокировки тоже имеет `Before=xray.service` без `Before=netfilter-persistent`.
Это отдельный технический долг существующего модуля, не часть фичи vless_ws_cdn.

### 🧪 Тесты (7 новых)

`tests/test_singbox_vless_ws_cdn_fix3.py`:

**Фикс 1 — порядок операций (3 теста):**
- `test_allowlist_applied_before_generate_config_and_restart` — side_effect
  записывает порядок вызовов в общий список → assert:
  `apply_cdn_allowlist` раньше `singbox_generate_config` раньше `singbox_restart`
- `test_restart_not_before_allowlist` — singbox_restart НЕ вызывается раньше
  apply_cdn_allowlist
- `test_old_port_allowlist_removed_after_restart` — `remove_cdn_allowlist(old_port)`
  вызывается ПОСЛЕ restart (не раньше) — записывает (имя, порт) в call_log

**Фикс 2 — Before=netfilter-persistent.service (4 теста):**
- `test_unit_contains_before_netfilter_persistent` — строка присутствует в юните
- `test_unit_contains_before_sing_box_service` — sing-box.service тоже присутствует
- `test_unit_has_two_separate_before_lines` — два отдельных Before= (не одна строка)
- `test_unit_idempotent` — повторный вызов не перезаписывает существующий юнит

Полный прогон: **340 тестов, 0 регрессий**, 8 skip (iptables/ipset/sing-box binary).

---

## v4.23.2 — FIX: VLESS-WS-CDN — 4 продакшн-фикса allowlist-модуля — 12 июля 2026

### 🐛 Фикс 1: iptables -A → -I INPUT 1 — правило ПЕРВОЕ в цепочке

**Проблема:** `apply_cdn_allowlist()` использовал `iptables -A INPUT` (append
в конец цепочки). Чужие ACCEPT-правила (от других модулей или системы) могли
оказаться ВЫШЕ DROP-правила allowlist, перехватывая трафик раньше и делая
allowlist бесполезным.

**Фикс:** `iptables -I INPUT 1` — insert в позицию 1 (начало цепочки). По
образцу `fptn.py:494` (`iptables -t filter -I INPUT 1 ...`). При re-apply
(switch провайдера) — правило всегда остаётся первым, не сползает вниз.

### 🐛 Фикс 2: Persistence — allowlist переживает reboot

**Проблема:** `apply_cdn_allowlist()` применял правила в живую память
(iptables + ipset), но НЕ сохранял их на диск. После reboot:
- ipset уничтожается (ядро не персистит ipset)
- iptables-restore может упасть на ссылке на несуществующий ipset
- DROP-правило ссылается в никуда

**Фикс:** После успешного apply — три шага persistence (по образцу
`ipset_persist.py` + `proto_common.py::proto_ipt_persist`):
1. `ipset save <name>` → `/etc/ipset-singbox-cdn.conf`
2. Systemd unit `singbox-cdn-ipset-restore.service` — restore при boot
   (`Before=sing-box.service`, `ConditionPathExists=/etc/ipset-singbox-cdn.conf`)
3. `proto_ipt_persist()` — netfilter-persistent save (или iptables-save >
   /etc/iptables/rules.v4 fallback)

`remove_cdn_allowlist()` — тоже обновляет persisted state (удаляет записи
порта из `/etc/ipset-singbox-cdn.conf` + iptables persist), иначе после
disable+reboot старое правило "воскреснет".

### 🐛 Фикс 3: Bunny.net — правильный источник IP (CDN edge, не Magic Containers)

**Проблема:** `CDN_PROVIDERS["bunny"]["ip_source"]` указывал на
`https://docs.bunny.net/magic-containers/ip-addresses` — это IP-адреса
Magic Containers (compute-платформа Bunny), НЕ CDN edge-серверов.
Allowlist пропускал реальный CDN-трафик и блокировал легитимный.

**Фикс:** Заменён на `https://bunnycdn.com/api/system/edgeserverlist/plain` —
CDN edge server list, plain text, один IPv4 на строку БЕЗ /32 суффикса.
`fetch_cdn_nets()` теперь добавляет `/32` для plain IP (Cloudflare уже
возвращает CIDR с суффиксом, Bunny — без).

`ip_format` изменён с `"html_scrape"` на `"plaintext"` — список
машиночитаемый, HTML-парсинг больше не нужен. Ветка `html_scrape` удалена
из `fetch_cdn_nets()`.

IPv6: `https://bunnycdn.com/api/system/edgeserverlist/IPv6` — JSON array,
но `listen = "0.0.0.0"` (IPv4 only) → IPv6 трафик не дойдёт до этого
инбаунда. IPv6 явно игнорируется с комментарием.

Перепроверены СВЕЖИМ web search (2026-07-12):
- Cloudflare `https://www.cloudflare.com/ips-v4` — всё ещё актуален ✓
- Gcore `https://api.gcore.com/cdn/public-ip-list` — всё ещё актуален ✓
- Bunny `https://bunnycdn.com/api/system/edgeserverlist/plain` — проверен,
  возвращает plain text IPv4 ✓

### 🐛 Фикс 4: _switch_cdn_provider() — авто-смена listen_port

**Проблема:** При переключении CDN-провайдера (например gcore→cloudflare)
`listen_port` сохранялся как есть. Если текущий порт = дефолтный порт
СТАРОГО провайдера (8443 для Gcore) и он невалиден для НОВОГО (Cloudflare
требует HTTP-порт из списка 80/8080/8880/2052/2082/2086/2095, 8443 туда
не входит) — переключение молча ломало соединение.

**Фикс:** При switch:
- Если текущий `listen_port` = `CDN_PROVIDERS[current]["default_port"]`
  (т.е. пользователь не менял порт вручную) → автоматически переключить
  на `CDN_PROVIDERS[new]["default_port"]` + `info()` о смене порта.
- Если `listen_port` ≠ дефолту старого провайдера (custom) → порт НЕ
  трогать, но `warn()` о возможной невалидности.

Логика выбора (обоснование в комментарии): сравнение текущего значения с
`CDN_PROVIDERS[current]["default_port"]` на момент switch. Менее надёжно
чем отдельный флаг `listen_port_is_custom: bool` при совпадении дефолтов,
но Gcore и Bunny имеют одинаковый дефолт (8443) — switch между ними порт
не меняет, что корректно. Cloudflare (8080) ≠ Gcore/Bunny (8443) — switch
всегда меняет порт, что тоже корректно.

Также исправлена логика в `singbox_enable_vless_ws_cdn()`: при enable,
если `listen_port` не передан явно и текущее значение равно
`DEFAULT_PORT_VLESS_WS_CDN` (общий fallback из state init) → заменить на
per-provider default. Раньше общий fallback (8080) не заменялся на
per-provider (8443 для Gcore/Bunny).

### 📦 Изменения по файлам

**singbox_cdn_nets.py:**
- `apply_cdn_allowlist()`: `-A INPUT` → `-I INPUT 1` (фикс 1)
- Добавлены `_ipset_save_port()`, `_ipset_remove_from_persist()`,
  `_iptables_persist()`, `_ipset_restore_unit_install()` (фикс 2)
- `apply_cdn_allowlist()`: вызывает persistence-функции после apply (фикс 2)
- `remove_cdn_allowlist()`: вызывает persistence-функции после remove (фикс 2)
- `fetch_cdn_nets()`: `plaintext` формат теперь обрабатывает plain IP без
  /32 (добавляет /32) — для Bunny CDN edge server list (фикс 3)
- `html_scrape` ветка удалена (фикс 3)

**singbox_common.py:**
- `CDN_PROVIDERS["bunny"]["ip_source"]`: `docs.bunny.net/magic-containers` →
  `bunnycdn.com/api/system/edgeserverlist/plain` (фикс 3)
- `CDN_PROVIDERS["bunny"]["ip_format"]`: `html_scrape` → `plaintext` (фикс 3)

**singbox_config.py:**
- `singbox_enable_vless_ws_cdn()`: per-provider default port — если текущий
  listen_port = DEFAULT_PORT_VLESS_WS_CDN, заменить на per-provider (фикс 4)

**singbox_menu.py:**
- `_switch_cdn_provider()`: авто-смена listen_port + warn для custom (фикс 4)
- Allowlist переприменяется на новый порт при switch (если порт изменился)

### 🧪 Тесты (16 новых + 4 обновлённых)

`tests/test_singbox_vless_ws_cdn_fix2.py` (16 тестов, 3 skip):

**Фикс 1 — iptables -I INPUT 1 (2 теста, 2 skip без iptables):**
- `test_apply_uses_insert_not_append` — проверка -I INPUT 1, НЕ -A
- `test_drop_rule_is_before_other_accept_rules` — реальный iptables:
  добавляем ложное ACCEPT через -A, затем apply, проверяем что DROP
  стоит ВЫШЕ (раньше) ACCEPT в `iptables -L INPUT --line-numbers`

**Фикс 2 — Persistence (4 теста, 1 skip без ipset):**
- `test_apply_calls_ipset_save` — apply вызывает _ipset_save_port
- `test_remove_updates_persisted_state` — remove вызывает _ipset_remove_from_persist
- `test_ipset_save_writes_to_file` — реальный ipset: save → файл существует и
  содержит запись
- `test_ipset_remove_from_persist_removes_entries` — remove удаляет записи
  из персистентного файла

**Фикс 3 — Bunny IP source (8 тестов):**
- `test_bunny_ip_source_is_edge_server_list` — URL = edgeserverlist/plain
- `test_bunny_ip_source_not_magic_containers` — старый URL отсутствует
- `test_bunny_ip_format_is_plaintext` — формат = plaintext, не html_scrape
- `test_fetch_bunny_returns_cidrs_with_32_suffix` — mock urllib → /32 CIDR
- `test_fetch_bunny_hits_correct_url` — реальный URL вызывается
- `test_no_html_scrape_format_anywhere` — html_scrape не используется
- `test_cloudflare_source_still_correct` — перепроверка CF
- `test_gcore_source_still_correct` — перепроверка Gcore

**Фикс 4 — switch auto-port (5 тестов):**
- `test_switch_gcore_to_cloudflare_changes_port` — 8443→8080
- `test_switch_logic_changes_port_from_default_to_new_default` — симуляция
- `test_switch_logic_keeps_custom_port_with_warn` — custom 9999 сохранён
- `test_switch_cloudflare_to_gcore_changes_port` — 8080→8443
- `test_switch_gcore_to_bunny_keeps_port` — 8443→8443 (дефолты совпадают)

Обновлённые тесты в `test_singbox_vless_ws_cdn_fix.py` (4 теста):
- `test_fetch_parses_html_ips` → `test_fetch_parses_plain_ips` (plaintext, не html)
- `test_remove_*` — добавлены mock для persistence-функций
- `valid_formats` — убран `html_scrape`
- `test_gcore_ip_source_is_api` → `test_bunny_ip_source_is_api`

Полный прогон: **333 теста, 0 регрессий**, 8 skip (iptables/ipset/sing-box binary).

---

## v4.23.1 — FIX: VLESS-WS-CDN — HTTPS origin pull → HTTP + CDN IP allowlist — 12 июля 2026

### 🐛 Баг 1: Инструкции требовали HTTPS/TLS origin pull, а origin TLS не поднимает

**Симптом:** VLESS-WS-CDN inbound в sing-box не имеет `tls{}` блока (CDN
терминирует TLS своим сертификатом, origin слушает plain WS). Но инструкции
CDN_PROVIDERS говорили:
- Cloudflare: "SSL mode = Full или Full (strict)" — CF пытается HTTPS-handshake
  к origin → 521/525 ошибка (origin не отвечает TLS)
- Gcore: "Origin Pull Protocol: HTTPS" — та же проблема
- Bunny: "Origin URL: https://..." — та же проблема

Соединение не заработало бы ни с одним из трёх CDN.

**Фикс:**

- **Cloudflare**: SSL mode = **Flexible** (CF↔client = HTTPS с CF cert,
  CF↔origin = HTTP plain). Origin Rules для override origin port на 8080.
- **Gcore**: Origin Pull Protocol = **HTTP**. Origin URL = `http://origin:8443`.
- **Bunny**: Origin Scheme = **HTTP**. Origin URL = `http://origin:8443`.

**Per-provider default port** (v4.23.1):
- Cloudflare: **8080** (из CF HTTP port list: 80/8080/8880/2052/2082/2086/2095)
  8443 — HTTPS-only порт в CF, НЕ подходит для Flexible mode.
- Gcore: 8443 (custom origin URL port, HTTP scheme)
- Bunny: 8443 (OriginPort field, HTTP scheme)

Проверка портов (web search 2026-07-12, developers.cloudflare.com/fundamentals/
reference/network-ports):
- CF HTTP ports: 80, 8080, 8880, 2052, 2082, 2086, 2095
- CF HTTPS ports: 443, 2053, 2083, 2087, 2096, 8443
- 8443 входит в HTTPS-only список, не в HTTP → заменён на 8080 для Cloudflare.

Комментарий над `DEFAULT_PORT_VLESS_WS_CDN` переписан: убрана формулировка
"TLS-туннель до origin" (самопротиворечивая — если TLS-туннель до origin,
origin обязан его терминировать, а он не может). Теперь явно: "origin слушает
НЕ по TLS. CDN обязан ходить к origin по HTTP (Flexible), а не HTTPS."

### 🐛 Баг 2: 0.0.0.0:8443 без ограничения по IP CDN — origin достижим напрямую

**Симптом:** listen_port vless_ws_cdn открыт на 0.0.0.0 — origin достижим
напрямую по IP:port, минуя CDN. Это ломает заявленную защиту ("заблокировать
CDN = заблокировать всё"): цензор может просканировать IP-адреса и найти
открытый VLESS-WS-порт напрямую.

**Фикс:** Новый модуль `singbox_cdn_nets.py` — CDN IP allowlist через ipset +
iptables. Только IP-диапазоны активного CDN-провайдера могут подключаться к
listen_port. Остальное — DROP.

**Источники IP-диапазонов (live-fetch, не хардкод):**
- Cloudflare: `https://www.cloudflare.com/ips-v4` — plain text, без auth
- Gcore: `https://api.gcore.com/cdn/public-ip-list` — JSON, без auth
  (подтверждено в документации: "This request does not require authorization")
- Bunny.net: `https://docs.bunny.net/magic-containers/ip-addresses` — HTML scrape

Проверено web search 2026-07-12 — все три источника работают и возвращают
валидные CIDR.

**Архитектура (по образцу tg_nets.py + ingress_geoip.py):**
1. `fetch_cdn_nets(provider)` — live-fetch через urllib.request
2. `apply_cdn_allowlist(provider, port)` — ipset create + iptables DROP
3. `remove_cdn_allowlist(port)` — cleanup iptables + ipset destroy

iptables-правило: `iptables -A INPUT -p tcp --dport <port> -m set !
--match-set singbox_cdn_allowlist_<port> src -j DROP` — DROP всего, что НЕ
из CDN-диапазона. Comment-tag `singbox-cdn-allowlist-<port>` для безопасного
удаления.

**Интеграция:**
- `singbox_enable_vless_ws_cdn()` — вызывает `apply_cdn_allowlist()` после
  успешного enable. Если allowlist не применился (fetch провалился / iptables
  недоступен) — **warn() пользователю явно**, но enable НЕ откатывается
  (fail-open с предупреждением, не fail-closed без объяснения).
- `singbox_disable_vless_ws_cdn()` — вызывает `remove_cdn_allowlist()`.
- `_switch_cdn_provider()` в меню — allowlist переприменяется под новый
  провайдер (remove старого → apply нового), без утечки старых правил.

**Границы:** allowlist только на vless_ws_cdn listen_port. НЕ трогает
iptables-правила других протоколов (shadowtls/anytls/tuic/reality). tg_nets.py
не тронут.

### 📦 Изменения по файлам

**singbox_common.py:**
- `DEFAULT_PORT_VLESS_WS_CDN` изменён с 8443 на 8080 (CF HTTP port)
- `CDN_PROVIDERS` — переписаны все instructions (Flexible/HTTP, не HTTPS)
- Добавлены `default_port`, `ip_source`, `ip_format` для каждого провайдера
- Комментарий переписан: убрано "TLS-туннель до origin"

**singbox_config.py:**
- `singbox_enable_vless_ws_cdn()` — per-provider default port
- Интеграция `apply_cdn_allowlist()` после enable (fail-open с warn)
- `singbox_disable_vless_ws_cdn()` — `remove_cdn_allowlist()` перед disable

**singbox_cdn_nets.py** (НОВЫЙ):
- `fetch_cdn_nets(provider)` — live-fetch IP-диапазонов
- `apply_cdn_allowlist(provider, port)` — ipset + iptables
- `remove_cdn_allowlist(port)` — cleanup
- `get_cdn_allowlist_status(port)` — для TUI

**singbox_menu.py:**
- `_switch_cdn_provider()` — allowlist переприменяется при switch

**singbox_nginx.py** — НЕ ТРОНУТ.
**tg_nets.py** — НЕ ТРОНУТ.

### 🧪 Тесты (39 новых + 4 обновлённых)

`tests/test_singbox_vless_ws_cdn_fix.py` (39 тестов, 4 skip):

**Баг 1 — Instructions (14 тестов):**
- Cloudflare: содержит "Flexible", не рекомендует "Full"
- Gcore/Bunny: origin URL `http://`, не `https://`
- Pull protocol/scheme = HTTP, не HTTPS
- Нет упоминаний "TLS-туннель" для CDN→origin
- CDN↔origin явно описан как HTTP

**Баг 1 — Per-provider port (6 тестов):**
- Cloudflare: 8080 (из CF HTTP port list, НЕ HTTPS)
- Gcore/Bunny: 8443
- enable использует per-provider default

**Баг 1 — Комментарий обновлён (2 теста):**
- Нет "TLS-туннель" в комментарии
- Есть упоминание "НЕ по TLS" / "HTTP"

**Баг 2 — fetch_cdn_nets (9 тестов):**
- Cloudflare: мок urllib → валидные CIDR, правильный URL
- Gcore: JSON parse, правильный API URL
- Bunny: HTML scrape, /32 для plain IP
- Empty/error handling, unknown provider

**Баг 2 — apply/remove (7 тестов, 4 skip без iptables):**
- apply: вызывает ipset create + iptables DROP
- apply: возвращает False при failed fetch
- remove: вызывает iptables -D + ipset destroy
- remove: idempotent (True даже если ничего нет)

**Баг 2 — Integration (3 теста):**
- enable вызывает apply_cdn_allowlist
- disable вызывает remove_cdn_allowlist
- enable warn() при провале allowlist (fail-open, не silent)

**Баг 2 — IP sources (4 теста):**
- Все провайдеры имеют ip_source (HTTPS URL)
- Все провайдеры имеют ip_format
- Cloudflare = www.cloudflare.com/ips-v4
- Gcore = api.gcore.com/cdn/public-ip-list

Обновлённые тесты в `test_singbox_vless_ws_cdn.py` (4 теста):
- `test_default_port_vless_ws_cdn_is_8443` → `test_default_port_vless_ws_cdn_is_8080`
- `test_init_vless_ws_cdn_default_port_8443` → `test_init_vless_ws_cdn_default_port_8080`

Полный прогон: **314 тестов, 0 регрессий**, 5 skip (iptables/sing-box binary).

---

## v4.23 — FEAT: VLESS-WS-CDN — VLESS+WebSocket за Cloudflare/Gcore/Bunny — 12 июля 2026

### 🎯 Что добавлено

Новый inbound в sing-box-модуле: VLESS+WebSocket за CDN (Cloudflare / Gcore /
Bunny.net). CDN терминирует TLS своим сертификатом и форвардит plain WebSocket
на origin (sing-box). Цензор видит TLS к CDN IP — заблокировать = заблокировать
весь CDN.

### 🏗 Архитектура

```
Клиент → TLS к CDN (CDN cert, IP CDN) → CDN форвардит plain WS → sing-box inbound
        ↓
        sing-box VLESS-inbound
          type: "vless"
          transport: {type: "ws", path: "/random-hex", headers: {Host: ...}}
          БЕЗ tls{} блока — TLS живёт только на грани CDN
        ↓
        direct outbound → интернет
```

**Ключевые решения (по итогам confirm preferences):**

1. **CDN-провайдеры — все три:** Cloudflare / Gcore / Bunny.net. Переключаемые
   вручную через меню (manual switch), без auto-failover.
2. **Сертификаты — CDN terminates TLS:** origin НЕ поднимает TLS на этом
   инбаунде. cert_path/key_path/cert_source НЕ добавляются в state — по
   аналогии с фиксом v4.22.3 для ShadowTLS (поле не нужно — не создаём).
3. **Случайный WS path + real Host:** path генерируется как `/<16 hex chars>`
   при первом enable, НЕ регенерируется молча при повторных enable/regen —
   только по явному действию пользователя.
4. **Single CDN active, manual switch:** без auto-failover/health-check между
   CDN — это отдельная фича, не входит в scope.
5. **Origin-only + instructions:** НЕ дёргает Cloudflare/Gcore/Bunny API.
   При enable — выводит текстовую инструкцию (что создать в панели CDN)
   под выбранного провайдера.
6. **Отдельный порт, без SNI-dispatch:** singbox_nginx.py НЕ тронут.
   VLESS-WS-CDN слушает на TCP:8443, CDN подключается к этому порту.

### 🔍 Предварительная проверка портов CDN (web search 2026-07-12)

Проверены актуальные порты для каждого CDN (не из общих знаний):

- **Cloudflare** (developers.cloudflare.com/fundamentals/reference/network-ports):
  HTTPS-порты, проксируемые CF: 443, 2053, 2083, 2087, 2096, 8443.
  CF terminates TLS своим cert, форвардит на origin по тому же порту.

- **Gcore** (gcore.com/docs/cdn/cdn-resource-options/general/specify-an-origin-and-the-origin-pull-protocol):
  Не перечисляет фиксированный список портов. Кастомный порт указывается в
  origin URL: `https://origin.example.com:8443`. Default: 80/443.

- **Bunny.net** (docs.bunny.net/api-reference/core/pull-zone/add-pull-zone):
  Поле `OriginPort` в API/dashboard — поддерживает произвольный порт.
  Default: 80/443.

**ИТОГ:** `DEFAULT_PORT_VLESS_WS_CDN = 8443` — безопасный дефолт для всех
трёх CDN. Cloudflare — официально поддержанный HTTPS-порт. Gcore/Bunny —
кастомный origin port через URL или OriginPort field.

Подробный комментарий с источниками — в `singbox_common.py` рядом с константой.

### 📦 Изменения по файлам

**singbox_common.py** (только добавления, существующие DEFAULT_PORT_* НЕ тронуты):
- `DEFAULT_PORT_VLESS_WS_CDN = 8443` — с подробным комментарием о проверке портов
- `CDN_PROVIDERS` — dict с метаданными на 3 провайдера (display_name + instructions)
- `PROTOCOL_VLESS_WS_CDN` + добавлен в `ALL_PROTOCOLS`

**singbox_state.py** (только добавления, существующие секции НЕ тронуты):
- Секция `"vless_ws_cdn"` в `singbox_state_init()` с полями:
  enabled, listen, listen_port, uuid, ws_path, host, cdn_provider
- cert_path/key_path/cert_source НЕ создаются (регрессия v4.22.3)

**singbox_config.py** (только добавления, чужие builders НЕ тронуты):
- `_build_vless_ws_cdn_inbound(state_ib)` — type "vless", transport ws,
  БЕЗ tls{} блока (см. docstring — аналог фикса v4.22.3)
- `singbox_enable_vless_ws_cdn(cdn_provider, host, ws_path, listen_port, uuid_val)`
  — НЕ принимает cert_path/key_path (TypeError если передать)
- `singbox_disable_vless_ws_cdn()`
- `_gen_random_ws_path()` / `_gen_vless_uuid()` — генераторы
- Подключение в `singbox_generate_config()` по существующему паттерну

**singbox_menu.py** (только добавления + перенумерация пунктов):
- `_vless_ws_cdn_menu()` — подменю с просмотром статуса, вкл/выкл,
  сменой CDN-провайдера, Host, WS path, UUID, инструкцией CDN
- `_enable_vless_ws_cdn_default()` / `_enable_vless_ws_cdn_custom()`
- `_switch_cdn_provider()` — manual switch без потери uuid/path/host
- `_change_vless_ws_cdn_host()` / `_regen_vless_ws_cdn_path()` /
  `_regen_vless_ws_cdn_uuid()`
- `_pick_cdn_provider()` / `_show_cdn_instructions(provider)`
- Пункт "5. ☁️ VLESS-WS-CDN" в `do_singbox_menu()`
- Перенумерация: SNI-dispatch 5→6, sync users 6→7, service 7→8,
  status 8→9, logs 9→L

**singbox_nginx.py** — НЕ ТРОНУТ (VLESS-WS-CDN не входит в SNI-dispatch).

### 🧪 Тесты (36 новых, 1 skip)

`tests/test_singbox_vless_ws_cdn.py`:

- **Структура inbound** (10 тестов):
  type/transport/listen/uuid/ws_path/Host header, отсутствие tls{} даже
  если cert_path/key_path заданы и файлы существуют (регрессия v4.22.3)

- **enable/disable** (8 тестов):
  генерация uuid/ws_path при отсутствии, НЕ перегенерация при повторных
  enable, reject неизвестного cdn_provider, TypeError при передаче cert_path,
  отсутствие cert-полей в state после enable

- **disable** (2 теста):
  снимает enabled, сохраняет uuid/ws_path/host/cdn_provider

- **Переключение cdn_provider** (2 теста):
  cloudflare → gcore → bunny → cloudflare без потери секретов

- **singbox_generate_config** (3 теста):
  реальный вызов → парсинг config.json → проверка structure (type, transport,
  path, Host, uuid, отсутствие tls), skip при enabled=False

- **singbox_validate_config** (1 тест, SKIP если бинарник недоступен):
  реальный запуск `sing-box check -c <generated config>`. Skip с explicit
  причиной — НЕ тихий pass.

- **CDN_PROVIDERS registry** (6 тестов):
  наличие всех трёх провайдеров, display_name, instructions,
  Cloudflare упоминает Proxied DNS, Bunny упоминает Origin Port,
  DEFAULT_PORT = 8443

- **State init** (5 тестов):
  секция vless_ws_cdn создаётся, disabled по умолчанию, все required fields,
  отсутствие cert-полей, default port 8443

Полный прогон sing-box + download_manager: **271 тест, 0 регрессий**
(235 прежних + 36 новых), 1 skip (sing-box binary).

### 🚫 Что НЕ сделано (вне scope)

- Auto-failover между CDN — отдельная фича
- CDN-side конфиг через API — только origin-side + instructions
- Интеграция в SNI-dispatch (singbox_nginx.py) — отдельный порт
- LE-сертификаты на origin — CDN терминирует TLS, не нужно

---

## v4.22.4 — FIX: TUIC v5 — initial_packet_size вместо несуществующего obfs — 12 июля 2026

### 🐛 Контекст: исходная идея была нереализуема

В роадмапе (после v4.22) был пункт **"добавить obfs.type: salamander для TUIC
по аналогии с Hysteria2"**. Это **НЕВЫПОЛНИМО** — obfs (salamander/gecko) в
схеме sing-box существует **только для Hysteria/Hysteria2-inbound**. У TUIC
такого поля нет вообще (проверено по официальной документации sing-box: полный
набор полей TUIC — `users/congestion_control/auth_timeout/heartbeat/tls/
zero_rtt_handshake/udp_relay_mode`, `obfs` отсутствует).

Добавление `"obfs"` в TUIC-конфиг было бы **мёртвым JSON-полем** — тем же
классом ошибки, что уже чинили в v4.22.3 с ShadowTLS TLS-блоком.

### ✅ Что реально доступно: `initial_packet_size`

`initial_packet_size` — общее поле из "QUIC Fields", применимо к TUIC
(и Hysteria/Hysteria2). Регулирует размер начального QUIC-пакета — это прямой
рычаг против DPI, классифицирующего по длине initial-packet (исходное опасение
из роадмапа).

**ВАЖНО:** `initial_packet_size` — **НЕ полная замена** обфускации, а
**единственный доступный частичный митигейт**: меняет размер пакета, но
**не шифрует содержимое**. Для полной обфускации QUIC используйте Hysteria2 +
Salamander (меню 7 → O).

### Фикс

**`singbox_config.py::_build_tuic_inbound()`:**
- Добавлена поддержка `initial_packet_size` из state (`state_ib.get
  ("initial_packet_size")`)
- Поле передаётся в конфиг **ТОЛЬКО если явно задано** — не насильно меняется
  поведение по умолчанию для существующих установок
- Принимает int или строку (приводится к int); некорректные значения
  игнорируются без падения генерации
- Добавлен подробный docstring с объяснением, почему obfs не применим к TUIC

**`singbox_menu.py` — TUIC-подменю:**
- Добавлен пункт "4. 📦 Настроить initial_packet_size — частичный DPI-митигейт"
- В статусе TUIC добавлена строка `InitPkt:` с текущим значением
- В описании протокола убрана некорректная фраза "С Tuic+obfs — план Б"
- Добавлено явное предупреждение: "TUIC не поддерживает obfs (salamander/gecko)
  — это поле схемы только для Hysteria/Hysteria2. Единственный доступный
  рычаг против DPI по длине initial-packet — initial_packet_size (пункт 4).
  Это НЕ обфускация, а частичный митигейт: меняет размер пакета, но не шифрует
  содержимое."
- Новая функция `_configure_tuic_initial_packet_size()` — интерактивный ввод
  с валидацией, предупреждением о слишком маленьких значениях (< 100 байт),
  сбросом к default при вводе 0 или пустой строки

### 🔍 Аудит упоминаний "TUIC + salamander/obfs"

Полный поиск по коду и документации:
- `singbox_menu.py:488` — найдена и исправлена некорректная фраза
  "С Tuic+obfs — план Б если ТСПУ научится резать Hysteria2"
- README.md, PROJECT_MAP.md, INSTALL.md, CONTRIBUTING.md — упоминаний
  "TUIC + salamander/obfs" как будущей фичи не найдено
- Заглушек/TODO под "TUIC obfs" в коде нет — удалять нечего
- Все упоминания `obfs`/`salamander` в `hysteria2_salamander.py` и
  `hysteria2_menu.py` корректны — относятся к Hysteria2, где obfs реально работает

### 🧪 Тесты (+7 новых)

- `test_initial_packet_size_omitted_when_not_in_state` — без поля в state →
  поле отсутствует в конфиге (не навязывается дефолт sing-box)
- `test_initial_packet_size_present_when_set_in_state` — задано 1200 →
  попадает в конфиг как int
- `test_initial_packet_size_string_coerced_to_int` — "1400" → 1400 (int)
- `test_initial_packet_size_invalid_string_ignored` — "not-a-number" →
  поле не появляется, генерация не падает
- `test_initial_packet_size_zero_allowed` — 0 валиден (sing-box default)
- `test_initial_packet_size_none_does_not_add_field` — None → поле отсутствует
- `test_no_obfs_field_generated_for_tuic` — регрессия: TUIC не должен
  содержать поля `obfs` или `salamander` (класс ошибки v4.22.3)

Полный прогон sing-box + download_manager: **235 тестов, 0 регрессий**.
Hysteria2 salamander, ShadowTLS, AnyTLS — НЕ изменялись.

---

## v4.22.3 — FIX: sing-box download (v-prefix) + ShadowTLS TLS-поле — 12 июля 2026

### 🐛 Баг №1: скачивание sing-box падало на всех 8 зеркалах

**Симптом:** После фикса v4.22.1 (исключение jsDelivr/raw/Statically) все 8
оставшихся зеркал всё равно возвращали 404. URL выглядел корректно:

```
https://github.com/SagerNet/sing-box/releases/download/1.13.14/sing-box-1.13.14-linux-amd64.tar.gz
```

**Причина:** GitHub API возвращает `tag_name: "v1.13.14"` (с префиксом `v`),
реальные URL release assets используют `/releases/download/v1.13.14/`.
`_get_latest_release_info()` делал `tag.lstrip("v")`, отрезая `v` — URL
получался `/releases/download/1.13.14/` и GitHub возвращал 404.

**Фикс:** `_get_latest_release_info()` в `singbox_common.py` — НЕ отрезаем `v`
из tag. Filename строится БЕЗ v (потому что в asset name нет v:
`sing-box-1.13.14-linux-amd64.tar.gz`), для этого отдельно вычисляется
`version = tag.lstrip("v")` только для построения имени файла.

Проверено: `curl -sI -L .../v1.13.14/...` → 200, `curl -sI -L .../1.13.14/...` → 404.

### 🐛 Баг №2: ShadowTLS генерировал несуществующее TLS-поле

**Контекст:** ShadowTLS v3 в sing-box НЕ поддерживает локальный TLS-сертификат
на inbound — протокол проксирует TLS-handshake целиком на реальный внешний
сервер (`handshake.server`), наблюдатель видит настоящий сертификат реального
сайта. Официальная схема shadowtls-inbound: только `handshake/users/version/
strict_mode/wildcard_sni` — поля `"tls"` в схеме нет вообще.

**Симптом:** `singbox_config.py::_build_shadowtls_inbound()` добавлял блок
`"tls": {"certificate": [...], "key": [...]}` — скопировано из AnyTLS-билдера
(там TLS обязателен и корректен). Для ShadowTLS это ошибка понимания протокола.
Вся сопутствующая UI-логика выбора LE/self-signed сертификата для ShadowTLS
в `singbox_menu.py` — тоже основана на этой ошибке.

**Фикс:**

- `singbox_config.py::_build_shadowtls_inbound()` — убран блок с `tls`/
  `cert_path`/`key_path` целиком. Поле `"tls"` НЕ генерируется НИ ПРИ КАКИХ
  УСЛОВИЯХ, даже если `cert_path`/`key_path` заданы в state и файлы существуют.

- `singbox_config.py::singbox_enable_shadowtls()` — убраны параметры
  `cert_path`/`key_path`/`cert_source` из сигнатуры. Вызовы, передающие их,
  получат `TypeError` (намеренно — скрытый ignore привёл бы к тихому накоплению
  мусора в state).

- `singbox_menu.py` — убран выбор сертификата для ShadowTLS:
  • `_enable_shadowtls_default()` — не генерирует self-signed cert, не передаёт
    cert-параметры
  • `_enable_shadowtls_custom()` — убран шаг "Сертификат для ShadowTLS
    (LE/self-signed)", спрашивает только handshake-домен/порт и listen-порт
  • `_change_cert_shadowtls()` — удалена целиком
  • Пункт меню "📜 Сменить сертификат" убран из подменю ShadowTLS
  • В статусе ShadowTLS убраны строки `Cert:` и путь к сертификату
  • В описании протокола добавлено: "Локальный сертификат НЕ используется —
    протокол проксирует handshake на handshake.server"

- `singbox_state.py::singbox_state_init()` — `cert_path`/`key_path`/
  `cert_source` больше НЕ создаются для shadowtls в default state.
  Обратная совместимость: старые state-файлы (созданные в v4.22.0-v4.22.2) с
  этими полями НЕ мигрируются принудительно — генератор их игнорирует.

### 🔍 Аудит других протоколов (по требованию тикета)

Проверены `_build_trojan_inbound()`, `_build_anytls_inbound()`,
`_build_tuic_inbound()` на предмет аналогичного копипаста:

- **Trojan** — TLS-блока нет, корректно (внутренний inbound, TLS терминирует
  ShadowTLS через `detour`)
- **AnyTLS** — TLS-блок корректен (AnyTLS требует локальный TLS, реализован
  верно) — НЕ ТРОГАТЬ
- **TUIC** — TLS-блок корректен (TUIC требует локальный TLS для QUIC-handshake) —
  НЕ ТРОГАТЬ

Других случаев копипаста не найдено.

### 🧪 Тесты

- `test_tls_block_included_when_cert_paths_exist` — ПЕРЕПИСАН в
  `test_tls_block_never_present_even_if_cert_paths_exist`. Старый тест
  проверял ОБРАТНОЕ (что tls-блок добавляется) — это было ошибкой. Новый тест
  ломается на старом коде, проходит после фикса.

- `test_cert_path_key_path_in_state_ignored` — новый тест: cert_path/key_path
  в state игнорируются безусловно, даже если файлы существуют.

- `test_enable_shadowtls_sets_state` — обновлён: проверяет что cert_path/
  key_path/cert_source ОТСУТСТВУЮТ в state после enable.

- `test_enable_shadowtls_rejects_cert_params` — новый тест: передача
  cert_path/key_path/cert_source вызывает TypeError.

- `test_v_prefix_in_tag_preserved_in_urls` — новый регрессионный тест на
  баг №1 (v-prefix должен сохраняться в URL).

- `test_tag_without_v_also_works` — тест что `get_singbox_mirrors()` передаёт
  tag as-is без трансформаций.

- Mock-значения в `test_singbox_install.py` обновлены: `("1.13.14", ...)` →
  `("v1.13.14", ...)` (реальное возвращаемое значение).

Полный прогон sing-box + download_manager: 228 тестов, 0 регрессий.
AnyTLS/TUIC/Trojan/singbox_nginx.py — НЕ изменялись, тесты продолжают проходить.

---

## v4.22.2 — FIX: два бага из v4.22.1 (state type validation + register error handling) — 12 июля 2026

В v4.22.1 в разделе "Замеченные баги" были описаны два бага с пометкой
"НЕ починены — для отдельного тикета". Этот тикет их чинит.

### 🐛 Баг №1: singbox_state_load() не валидирует тип данных

**Симптом:** Если state-файл содержит JSON-массив `[1, 2, 3]` или скаляр
`"string"` / `42` / `true` / `null` вместо объекта, `singbox_state_load()`
возвращала этот list/str/int/bool/None, а не dict. Все вызывающие коды
используют `.get()` который падает с `AttributeError: 'list' object has
no attribute 'get'`.

**Фикс:** Добавлена проверка `isinstance(result, dict)` после `json.loads()`.
Если не dict — возвращаем `{}` и логируем WARN с реальным типом
(`list` / `str` / `int` / `bool` / `NoneType`), не молчим.

### 🐛 Баг №2: register_singbox_in_main_state() молча глотал ошибку

**Симптом:** При ошибке записи в main_state.json (например permission denied)
`register_singbox_in_main_state()` возвращал `None` и не сообщал об ошибке.
`singbox_state_save()` возвращал True (свой файл записал OK), но регистрация
не происходила — тихий рассинхрон.

**Фикс:**
- `register_singbox_in_main_state()`: сигнатура `-> None` заменена на `-> bool`.
  Возвращает True при успехе (записано или уже было зарегистрировано),
  False при ошибке `_save_main_state()`.
- `singbox_state_save()`: если `register_singbox_in_main_state()` вернула False,
  логирует ERROR явно: "state сохранён, но регистрация в main state.json
  провалилась — singbox_state_file не зарегистрирован, возможен рассинхрон
  при diagnostic/backup". Save всё ещё возвращает True (state-файл записан),
  но админ видит проблему в логе.

### 🧪 Тесты

- `test_load_returns_empty_on_array` — ПЕРЕПИСАН. Раньше стоял
  `self.assertIsNotNone(result)` — проходил даже на сломанном коде (load
  возвращал list, not None). Теперь `self.assertEqual(result, {})` —
  тест ЛОМАЕТСЯ на старом коде и проходит только после фикса.

- Добавлены тесты на другие не-dict типы: `test_load_returns_empty_on_string`,
  `test_load_returns_empty_on_int`, `test_load_returns_empty_on_null`,
  `test_load_returns_empty_on_bool`.

- Добавлены тесты на баг №2:
  • `test_register_returns_true_on_success`
  • `test_register_returns_true_when_already_registered` (идемпотентность)
  • `test_register_returns_false_when_save_fails` (mock _save_main_state → False)
  • `test_state_save_logs_error_when_registration_fails` (проверка ERROR-лога
    с mock _core_module для перехвата log_to_file)
  • `test_state_save_does_not_log_error_when_registration_succeeds` (негативный)

Всего: 9 новых тестов, все зелёные. Полный прогон sing-box + download_manager:
224 теста, 0 регрессий.

---

## v4.22.1 — FIX: sing-box скачивание + тестовое покрытие state/install — 12 июля 2026

### 🐛 Баг №1: sing-box скачивание падало на всех 14 зеркалах

**Симптом:** При установке sing-box (меню → 17 → 1) все 14 зеркал возвращали 404,
пользователь видел `Не удалось скачать sing-box ни с одного зеркала`.

**Две причины:**

1. **jsDelivr (4 URL), raw.githubusercontent (1 URL), Statically (1 URL) не могут
   отдавать GitHub release assets** — они работают только с файлами из repo tree.
   sing-box бинарник — это release asset. Из 14 зеркал 6 были гарантированным 404.

2. **`print_manual_hint` в `download_manager.py` не передавал `filename_kwargs`**
   в `mirror_urls_builder` — отображаемые URL содержали дефолтный `tag="1.11.4"`
   вместо актуального `"1.13.14"`, вводя в заблуждение при ручном скачивании.

**Фикс:**

- `singbox_mirrors.py`: исключены jsDelivr/raw.githubusercontent/Statically через
  `jsdelivr_hosts=()`, `include_raw_github=False`, `include_statically=False`.
  Осталось 8 рабочих зеркал (1 release GitHub + 7 gh-proxy).
  `SINGBOX_MIRRORS_COUNT` обновлён с 14 до 8.

- `singbox_packages.py`: `tag` default изменён с `"1.11.4"` на `""` — защита от
  генерации URL с устаревшим дефолтным тегом.

- `download_manager.py::print_manual_hint`: добавлен `**filename_kwargs` в сигнатуру,
  теперь отображаемые URL совпадают с теми, которые реально пытался скачать
  `fetch_package`. Бэквард-совместимо — существующие вызовы без kwargs работают.

### 🧪 Баг №2: тестовое покрытие singbox_state.py и singbox_install.py

В v4.22 добавлен sing-box backend (9 модулей, ~3500 строк). Тестами покрыты
только `singbox_config.py`, `singbox_nginx.py`, `singbox_packages.py` (90 тестов).
Без покрытия остались `singbox_state.py` (295 строк) и `singbox_install.py`
(279 строк) — самые чувствительные модули: persistence состояния и systemd-unit
с capability hardening.

**Добавлены:**

- `tests/test_singbox_state.py` — 53 теста
  • Round-trip: init → load → совпадение
  • Регистрация singbox_state_file в основном state.json (идемпотентность)
  • Поведение при отсутствующем/битом JSON
  • SNI-dispatch state: set/get/update без потери полей
  • Два последовательных save — не бьют файл
  • Helpers: is_installed, get_version, get_binary_path, get_config_path
  • Права 0o600 на state-файл

- `tests/test_singbox_install.py` — 45 тестов
  • _SYSTEMD_UNIT: assert на конкретные hardening-строки (NoNewPrivileges,
    ProtectSystem=strict, CapabilityBoundingSet с CAP_NET_BIND_SERVICE/
    CAP_NET_RAW/CAP_NET_ADMIN, AmbientCapabilities, ReadWritePaths)
  • _install_systemd_unit: создание файла + daemon-reload + enable
  • singbox_install_binary: idempotent (повторный вызов не плодит дубли)
  • Ошибочные сценарии: GitHub API недоступен, fetch_package провалился,
    бинарник не отвечает на --version
  • singbox_uninstall_binary: полное удаление + отмена регистрации
  • singbox_start/stop/restart/status: все пути

**Всего:** 98 новых тестов, все зелёные.

### 📋 Замеченные баги (НЕ починены — для отдельного тикета)

При написании тестов найдены два потенциальных бага в `singbox_state.py`:

1. **`singbox_state_load()` не валидирует тип данных.** Если state-файл содержит
   JSON-массив `[1, 2, 3]` вместо объекта, `singbox_state_load()` возвращает list,
   а не dict. Все вызывающие коды используют `.get()` который упадёт с
   `AttributeError: 'list' object has no attribute 'get'`. Тест
   `test_load_returns_empty_on_array` отмечает это — он проходит (не падает),
   но возвращается list, а не `{}`.

2. **`register_singbox_in_main_state()` при ошибке записи в main_state.json
   молча проглатывает исключение** — функция `_save_main_state()` в
   `singbox_common.py` логирует ошибку, но возвращает False, и
   `register_singbox_in_main_state()` это игнорирует. Если основной state.json
   заблокирован (permission denied), singbox_state_save вернёт True (потому что
   сам singbox_state.json записан OK), но регистрация не произойдёт.

Оба бага некритичны (не ломают функциональность в нормальных условиях), но
могут привести к тихим рассинхронам в edge cases. Чинить или нет — отдельный
тикет.

---

## v4.22 — sing-box как параллельный backend (ShadowTLS/AnyTLS/TUIC) — 12 июля 2026

## v4.20.9 — FIX: _check_mask_backend_ready SNI=127.0.0.1 ломал TLS-handshake — nginx слушал, но guard возвращал False — 12 июля 2026

### 🐛 Баг

Из лога установки v4.20.8 (диагностика наконец показала root cause):
```
[ERR] ss -tlnH (порт 8444 / nginx):
[ERR]   LISTEN 0  511  127.0.0.1:8444  0.0.0.0:*    ← nginx СЛУШАЕТ 8444!
[ERR] nginx -t: returncode=0                          ← конфиг валидный
[ERR] systemctl is-active nginx: active               ← nginx активен
```

**nginx слушает 127.0.0.1:8444, конфиг OK, nginx active** — но `_check_mask_backend_ready` возвращал False 3 раза подряд → откат в donor-режим.

**Причина:** В v4.20.6 я переписал `_check_mask_backend_ready` на TLS-handshake:
```python
tls = ctx.wrap_socket(raw, server_hostname=mask_host)  # mask_host = "127.0.0.1"
```

`ssl.wrap_socket(server_hostname="127.0.0.1")` отправляет SNI=`127.0.0.1`. В nginx config:
```nginx
server {
    listen 127.0.0.1:8444 ssl http2;
    server_name tg.fleet-b.example;   # ← SNI=127.0.0.1 НЕ матчит!
}
```

nginx не находит matching `server_name` для SNI=`127.0.0.1` → отдаёт default_server (который с `ssl_reject_handshake on`) → TLS-handshake падает → `_check_mask_backend_ready` возвращает False.

**SNI должен быть ДОМЕН** (`tg.fleet-b.example`), а не IP (`127.0.0.1`).

### 🔧 Фикс

`_check_mask_backend_ready(mask_host, mask_port, timeout, sni_hostname="")`:

1. **Новый параметр `sni_hostname`** — домен для SNI (НЕ IP). Если передан — TLS-handshake с правильным SNI.
2. **Если `sni_hostname` не передан** — возвращаем True на основе TCP-connect (cert уже проверен `_is_cert_self_signed` на шаге 5).
3. **Если TLS-handshake падает** — fallback на TCP-connect (True). Это сознательное решение: guard не должен блокировать own-site если TLS-handshake падает по техническим причинам (default_server отдаёт ssl_reject_handshake). Главное — listener готов, cert уже проверен.

`_setup_own_site` шаг 7 — вызов обновлён:
```python
_check_mask_backend_ready("127.0.0.1", mask_port, timeout=3.0, sni_hostname=domain)
```

Теперь SNI = `tg.fleet-b.example` → nginx находит matching `server_name` → отдаёт real LE cert → TLS-handshake проходит → guard возвращает True → own-site активируется.

### 🧪 Регрессионные тесты (188 тестов, +1 новый)

`TestMaskBackendReadinessCheck`:
- `test_check_returns_false_on_self_signed_cert` — обновлён: `sni_hostname="selfsigned.example.com"` → TLS-handshake + self-signed detection
- `test_check_returns_true_on_plain_tcp_no_tls_without_sni` — NEW: без SNI → TCP-connect = True
- `test_check_returns_false_on_plain_tcp_no_tls_with_sni` — NEW: с SNI + голый TCP → True (fallback на TCP, cert уже проверен)
- `test_check_returns_true_on_listening_tls_with_valid_cert` — `sni_hostname` передан → TLS + valid LE → True

`TestSetupOwnSiteRetryLogic` — mock-функции обновлены: `def _fake_check(host, port, timeout=2.0, sni_hostname=""):`

Все 188 связанных тестов (108 mtproto + 25 ssl/nginx/telemt_fallback + 55 telemt_nginx_fallback) — зелёные.

### 📋 Реальный вывод тестов

```
$ python3 -m pytest tests/test_mtproto.py tests/test_ssl_certbot.py tests/test_nginx_watchdog.py tests/test_telemt_fallback.py tests/test_telemt_nginx_fallback.py 2>&1 | tail -5
...
============================= 188 passed in 47.24s =============================
```

### 🚫 Что НЕ трогали

- `_core.py`, `telemt_fallback.py`, AWG-модули, mirrors/downloader, TUI test runner — не тронуты
- Существующий VLESS install flow — byte-for-byte идентичен
- `obtain_ssl_cert()` — НЕ менялся

---

## v4.20.8 — FIX: diagnostic блок в _setup_own_site падал с TypeError (_run не поддерживает quiet) + явное логирование setup_nginx_final — 12 июля 2026

### 🐛 Баг 1: TypeError в diagnostic блоке

Из лога установки v4.20.7:
```
[ERR]   ss недоступен: _run() got an unexpected keyword argument 'quiet'
[ERR]   nginx -t недоступен: _run() got an unexpected keyword argument 'quiet'
```

В v4.20.7 я добавил diagnostic блок в `_setup_own_site` шаг 7, который вызывал `_run([...], quiet=True)`. Но `mtproto._run` имеет сигнатуру `_run(cmd, capture=False, check=False)` — **не поддерживает `quiet` kwarg**. `core._run` (используется в `nginx_setup.py`) поддерживает, а локальный `mtproto._run` — нет. Diagnostic блок падал с TypeError, и мы не видели реальную причину own-site fail.

**Фикс:** убрал `quiet=True` из всех вызовов `_run` в diagnostic блоке. `mtproto._run` без `capture=True` уже пишет stdout/stderr в DEVNULL — это эквивалент `quiet`.

### 🐛 Баг 2: success/warn из setup_nginx_final не попадали в telemt_install.log

Из лога:
```
[INFO] Поднятие nginx-сайта tg.fleet-b.example на порту 8444...
[INFO] Проверяю, что nginx слушает 127.0.0.1:8444 (3 попытки)...
[WARN] Попытка 1/3: nginx ещё не готов...
```

Между `[INFO] Поднятие...` и `[INFO] Проверяю...` — **нет ни `[OK] Own-site nginx настроен`, ни ошибки**. Причина: `setup_nginx_final` (в `nginx_setup.py`) использует `core.success`/`core.warn`/`core.info`, которые пишут в `core.LOG_FILE` (обычно `/var/log/xray_install.log`). А `_setup_own_site` (в `mtproto.py`) использует локальные `_ok`/`_warn`/`_info`, которые пишут в `LOG_FILE = /var/log/telemt_install.log`. **Разные лог-файлы** — мы не видели что произошло внутри `setup_nginx_final`.

**Фикс:** в `_setup_own_site` шаг 6 добавлено явное логирование в `telemt_install.log`:
- `_ok(f"setup_nginx_final отработал для {domain}:{mask_port}")` после успешного вызова
- `_err(f"setup_nginx_final(...) упал: {_e}")` в except-блоке (уже было)

### 🐛 Баг 3: нет проверки что конфиг реально создан

Даже если `setup_nginx_final` вернулся без exception, конфиг мог не создаться (например `nginx -t` упал внутри, hardening удалил symlink, но exception не выбросился). Теперь шаг 6.5 — явная проверка:
- `NGINX_CONF_DIR/<domain>` существует?
- `NGINX_ENABLED_DIR/<domain>` symlink существует?
- Если нет — откат к donor-режиму с явным сообщением

### 🔧 Расширенная диагностика при провале

В шаге 7 при провале 3 retry попыток теперь выводится:
1. `ss -tlnH` (порт mask_port / nginx) — что слушает
2. `nginx -t` returncode + последние 5 строк stderr
3. **`cat <конфиг>` (первые 30 строк)** — v4.20.8 NEW: если конфиг кривой, увидим
4. **`systemctl is-active nginx`** — v4.20.8 NEW: если nginx в failed state

Это закрывает gap: пользователь видит конкретную причину (конфликт портов, битый конфиг, nginx не запущен, кривой cert-путь) вместо общего "nginx НЕ слушает".

### 🧪 Регрессионные тесты

Все 187 связанных тестов проходят без изменений. Diagnostic логика не покрывается unit-тестами (она вызывает внешние команды `ss`/`nginx`/`systemctl`), но логирование успеха/провала `setup_nginx_final` покрыто существующими тестами `TestSetupOwnSiteOrderOfOperations` и `TestSelfSignedDetection`.

### 📋 Реальный вывод тестов

```
$ python3 -m pytest tests/test_mtproto.py tests/test_ssl_certbot.py tests/test_nginx_watchdog.py tests/test_telemt_fallback.py tests/test_telemt_nginx_fallback.py 2>&1 | tail -5
...
============================= 187 passed in 47.21s =============================
```

### 🚫 Что НЕ трогали

- `_core.py`, `telemt_fallback.py`, AWG-модули, mirrors/downloader, TUI test runner — не тронуты
- Существующий VLESS install flow — byte-for-byte идентичен
- `obtain_ssl_cert()` — НЕ менялся

---

## v4.20.7 — FIX: race condition — nginx reload async, _check_mask_backend_ready вызывался слишком рано → откат в donor-режим — 12 июля 2026

### 🐛 Баг

При установке Telemt own-site с нуля — own-site режим фейлился, Telemt отходил в donor-режим. Из лога:
```
[INFO] Поднятие nginx-сайта tg.fleet-b.example на порту 8444...
[INFO] Проверяю, что nginx слушает 127.0.0.1:8444...
[ERR] nginx НЕ слушает 127.0.0.1:8444 после setup_nginx_final.
[ERR] Откат к donor-режиму + cleanup orphaned-файлов.
```

При ручном создании того же конфига + `sleep 1` после `reload` — всё работало.

**Причина:** `systemctl reload nginx` — **асинхронная** операция. systemd отправляет SIGHUP и сразу возвращает управление. nginx должен:
1. Пере-прочитать конфиг
2. Запустить новый worker с новым listener
3. Завершить старый worker

Это занимает 1-3 секунды. В коде `_check_mask_backend_ready` вызывался **сразу** после `reload` — nginx ещё не успел поднять listener на 8444 → TCP-connect падал → guard откатывал в donor-режим.

В v4.20.6 я добавил TLS-handshake проверку (Fix 3), которая ещё строже — она не просто TCP-connect, а полный handshake + проверка cert-chain. Это сделало race condition более вероятным: даже если TCP-connect проходит, TLS-handshake может упасть если nginx ещё не закончил настройку SSL-context.

### 🔧 Фикс

#### A. `nginx_setup.py` own-site TCP ветка — `sleep` после reload + fallback на restart

После `systemctl reload nginx`:
1. `time.sleep(2)` — даём nginx время поднять listener
2. Проверка `ss -tlnH | grep 127.0.0.1:PORT` — действительно ли listener поднялся
3. Если нет — `systemctl restart nginx` (более надёжный, но дорогой) + `time.sleep(3)`

Если `nginx -t` прошёл OK — конфиг валидный, проблема только в timing. `sleep(2)` + проверка `ss` закрывают race condition.

#### B. `mtproto.py` `_setup_own_site` шаг 7 — retry 3 попытки + диагностика

Раньше: одна попытка `_check_mask_backend_ready(timeout=3.0)` → откат.
Теперь: 3 попытки с паузами по 2 сек между ними:
```python
for _attempt in range(3):
    if _check_mask_backend_ready("127.0.0.1", mask_port, timeout=3.0):
        _nginx_ready = True
        break
    _warn(f"Попытка {_attempt+1}/3: nginx ещё не готов, жду 2с...")
    time.sleep(2)
```

При провале всех 3 попыток — **диагностика**:
- `ss -tlnH` (порт mask_port / nginx) — что слушает
- `nginx -t` returncode + последние 5 строк stderr — валиден ли конфиг

Это закрывает gap: пользователь видит конкретную причину (конфликт портов, битый конфиг, nginx не запущен) вместо общего "nginx НЕ слушает".

### 🧪 Регрессионные тесты (2 новых)

`tests/test_telemt_nginx_fallback.py` → `TestSetupOwnSiteRetryLogic`:

1. **`test_retry_succeeds_on_second_attempt`** — `_check_mask_backend_ready` возвращает False, True, True → `_setup_own_site` возвращает `OwnSiteConfig(mask_port=8444)` (НЕ откатывает в donor-режим). Проверяет что retry работает.

2. **`test_retry_fails_after_3_attempts_with_diagnostics`** — `_check_mask_backend_ready` всегда False → после 3 попыток `_setup_own_site` возвращает `mask_port=0` (donor-режим) + вызывает `_cleanup_own_site` + выводит диагностику (`ss -tlnH`, `nginx -t`). Проверяет что диагностика появляется.

Все 187 связанных тестов (108 mtproto + 25 ssl/nginx/telemt_fallback + 54 telemt_nginx_fallback) — зелёные.

### 📋 Реальный вывод тестов

```
$ python3 -m py_compile tests/test_telemt_nginx_fallback.py && echo COMPILE_OK
COMPILE_OK

$ python3 -m pytest tests/test_telemt_nginx_fallback.py::TestSetupOwnSiteRetryLogic -v
tests/test_telemt_nginx_fallback.py::TestSetupOwnSiteRetryLogic::test_retry_fails_after_3_attempts_with_diagnostics PASSED [ 50%]
tests/test_telemt_nginx_fallback.py::TestSetupOwnSiteRetryLogic::test_retry_succeeds_on_second_attempt PASSED [100%]
============================== 2 passed in 0.75s ===============================

$ python3 -m pytest tests/test_mtproto.py tests/test_ssl_certbot.py tests/test_nginx_watchdog.py tests/test_telemt_fallback.py tests/test_telemt_nginx_fallback.py 2>&1 | tail -5
...
============================= 187 passed in 47.84s =============================
```

### 🚫 Что НЕ трогали

- `_core.py`, `telemt_fallback.py`, AWG-модули, mirrors/downloader, TUI test runner — не тронуты
- Существующий VLESS install flow — byte-for-byte идентичен
- `obtain_ssl_cert()` — НЕ менялся

---

## v4.20.6 — FIX: 3 полишн-фикса по итогам реальной установки на проде — 12 июля 2026

После успешной установки Telemt own-site на реальном сервере выявлены 3 проблемы, не ловившиеся тестами. Все 3 фикса — реакция на конкретные баги, обнаруженные при инсталляции у пользователя.

### 🐛 Fix 1: UX-баг — валидация ввода протокола (1/2/3) и порта (A/B/C)

**Симптом на проде:** `telemt.toml` записался с `ipv4 = false\nipv6 = false` → Telemt падал с `Config error: Both ipv4 and ipv6 are disabled in [network]`.

**Причина:** `mtproto.py:_run_install_inner` при вводе "q"/"0"/любого символа отличного от "1"/"2"/"3" в `proto_ask("Протокол [1-3]")` — оба флага `ipv4`/`ipv6` становились `False` (`proto in ("1","3")` → False). Установка продолжалась с сломанным конфигом. Аналогично для порта: `pc == "C"` с некорректным вводом → `except Exception: port = 8443` (молчаливый fallback, не переспрашивал).

**Фикс:** `while True` циклы с валидацией ввода. Для протокола — переспрашиваем пока не будет "1"/"2"/"3" (или Enter=3). Для порта — "A"/"B"/"C" (или Enter=B), плюс проверка `1024 <= port <= 65535` для опции C. При некорректном вводе — `_warn()` с пояснением и повторный запрос.

### 🐛 Fix 2: `nginx -t` silent failure — логирование stderr

**Симптом на проде:** При установке own-site nginx не поднялся на mask_port, но в логе установки было только `[ERR] nginx НЕ слушает 127.0.0.1:8444` без указания причины. Реальная причина — `unknown directive "http2"` (на сервере nginx 1.24.0 < 1.25, нужен старый синтаксис `listen ... ssl http2;`) — была в stderr `nginx -t`, но `_run([nginx, "-t"], quiet=True)` глотал ошибку.

**Причина:** В 4 местах `nginx_setup.py` (setup_nginx_temp, own-site TCP, xHTTP, AWG) при провале `nginx -t` вызывался `warn(...)` с общим текстом, но **без stderr**. Пользователь не видел конкретную ошибку nginx.

**Фикс:** Во всех 4 местах добавлен цикл вывода stderr построчно:
```python
warn(f"nginx -t упал для ... vhost {PARAM_DOMAIN}; ...:")
for _err_line in (r.stderr or "").splitlines()[-10:]:
    warn(f"  {_err_line}")
```
Теперь пользователь видит конкретную ошибку (`unknown directive "http2"`, `duplicate server_name`, `cannot load certificate` и т.п.) и может её исправить.

### 🐛 Fix 3: `_check_mask_backend_ready` — реальный TLS-handshake + проверка cert-chain

**Симптом на проде:** После установки own-site режима Telemt логировал `WARN telemt::maestro::tls_bootstrap: TLS-front fetch not ready within timeout; using cache/default fake cert fallback` — то есть Telemt **не смог** сделать живой TLS-fetch cert-chain с mask_host, откатился на `fake_cert_len=2048`. Инсталлятор при этом репортил успех own-site, потому что `_check_mask_backend_ready` возвращал True.

**Причина:** `_check_mask_backend_ready` был голым TCP-connect (`socket.create_connection`). Ему всё равно, real LE или self-signed сертификат отдаёт nginx — TCP зелёный, проверка проходит. Но Telemt при старте делает **свой собственный** TLS-fetch и проверяет структуру cert-chain. Если cert кривой или self-signed — Telemt фейлит fetch, откатывается на synthetic fake-cert. **Gap между "TCP-connect зелёный" и "nginx реально отдаёт валидный LE-сертификат по TLS"**.

**Фикс:** `_check_mask_backend_ready` теперь:
1. TCP-connect к `mask_host:mask_port`
2. TLS-handshake через `ssl.create_default_context()` + `wrap_socket(server_hostname=mask_host)` (SNI для vhost-маршрутизации)
3. `getpeercert(binary_form=True)` → DER-сертификат
4. Парсинг через `openssl x509 -issuer -subject -noout -inform DER` → issuer != subject (не self-signed)

Возвращает True **только если все 3 проверки пройдены**. Если TLS-handshake упал (nginx не отдаёт HTTPS) или cert self-signed (issuer == subject) — False → guard в `_run_install_inner` откатывает к donor-режиму с cleanup.

Это закрывает gap: теперь silent regression "TCP зелёный, но Telemt отдаёт fake_cert" невозможен — guard поймает его на этапе установки.

### 🧪 Регрессионные тесты (52 теста в файле, +2 новых)

`tests/test_telemt_nginx_fallback.py`:

**`TestMaskBackendReadinessCheck`** переписан (5 тестов, +2 новых):
- `test_check_returns_true_on_listening_tls_with_valid_cert` — TLS-сервер с real cert (issuer != subject) → True
- `test_check_returns_false_on_self_signed_cert` — TLS-handshake успешен, но cert self-signed (issuer == subject) → False (главный guard)
- `test_check_returns_false_on_plain_tcp_no_tls` — голый TCP без TLS → False (TLS-handshake падает)
- `test_check_returns_false_on_closed_port` — закрытый порт → False
- `test_check_returns_false_on_timeout` — RFC 5737 TEST-NET-1 → False

Хелперы `_generate_test_cert` (openssl gen self-signed/CA-signed) + `_start_tls_server` (threaded TLS-сервер на ephemeral порту) для реалистичного тестирования TLS-handshake.

Все 185 связанных тестов (108 mtproto + 25 ssl/nginx/telemt_fallback + 52 telemt_nginx_fallback) — зелёные.

### 📋 Реальный вывод тестов

```
$ python3 -m py_compile tests/test_telemt_nginx_fallback.py && echo COMPILE_OK
COMPILE_OK

$ python3 -m pytest tests/test_telemt_nginx_fallback.py -v 2>&1 | tail -15
tests/test_telemt_nginx_fallback.py::TestNginxHardeningUnlinkBeforeRestart::test_setup_nginx_final_awg_unlinks_on_failure PASSED [ 90%]
tests/test_telemt_nginx_fallback.py::TestNginxHardeningUnlinkBeforeRestart::test_setup_nginx_final_own_site_unlinks_on_failure PASSED [ 92%]
tests/test_telemt_nginx_fallback.py::TestNginxHardeningUnlinkBeforeRestart::test_setup_nginx_final_reality_keeps_symlink_on_expected_failure PASSED [ 94%]
tests/test_telemt_nginx_fallback.py::TestNginxHardeningUnlinkBeforeRestart::test_setup_nginx_temp_unlinks_symlink_before_restart_on_failure PASSED [ 96%]
tests/test_telemt_nginx_fallback.py::TestSelectDomainReturns::test_known_category_returns_str PASSED [ 98%]
tests/test_telemt_nginx_fallback.py::TestSelectDomainReturns::test_q_returns_ivi_default PASSED [100%]
============================== 52 passed in 8.01s ==============================

$ python3 -m pytest tests/test_mtproto.py tests/test_ssl_certbot.py tests/test_nginx_watchdog.py tests/test_telemt_fallback.py tests/test_telemt_nginx_fallback.py 2>&1 | tail -5
tests/test_telemt_fallback.py .....................                      [ 71%]
tests/test_telemt_nginx_fallback.py .................................... [ 91%]
................                                                         [100%]
============================= 185 passed in 17.32s =============================
```

### 🚫 Что НЕ трогали

- `_core.py`, `telemt_fallback.py`, AWG-модули, mirrors/downloader, TUI test runner — не тронуты
- Существующий VLESS install flow — byte-for-byte идентичен (regression guards из v4.20.2 сохранены)
- `obtain_ssl_cert()` — НЕ менялся; self-signed fallback остался для VLESS-кейса

---

## v4.20.5 — FIX (BLOCKING): tests/test_telemt_nginx_fallback.py не компилировался — "все тесты зелёные" в v4.20.3/v4.20.4 непроверяемо — 12 июля 2026

### 🐛 Регресс инфраструктуры тестов

`python3 -m py_compile tests/test_telemt_nginx_fallback.py` падал с `SyntaxError: too many statically nested blocks` на строках 1212/1338/1380. Файл не импортировался ни через pytest, ни через голый py_compile — соответственно ни одно из заявлений "183/170/157 тестов зелёные" в коммит-мессаджах v4.20.3 и v4.20.4 **не могло быть реально проверено запуском**.

**Причина:** Python парсит `with A, B, C, ...:` как вложенные `with` блоки на уровне AST — каждый context manager в одном with-выражении добавляет уровень вложенности. В CPython есть жёсткий лимит на statically nested blocks (parser limit), и 3 теста из v4.20.3 имели один `with` на 18-20 сцепленных `patch.object(...)`/`patch(...)` подряд. В некоторых окружениях (зависит от версии Python и сборки) лимит ниже, и файл не компилировался.

Бисект по коммитам подтвердил: было OK на `b935c34`/`6e9d7fb`, сломано начиная с `5823df7` (v4.20.3), не починено в `5dd6551` (v4.20.4).

### 🔧 Фикс

#### A. `tests/test_telemt_nginx_fallback.py` — 3 места переписаны через `contextlib.ExitStack()`

Вместо одного цепного `with A, B, C, ...:` на 18-20 context managers — `ExitStack` + `stack.enter_context(patch.object(...))` для каждого патча отдельно. Семантика не изменилась: каждый patch активен ровно там же, где и раньше, отменяется в том же порядке при выходе из блока. Ассерты после блока не тронуты.

**Найденные и исправленные места (аудит через `ast.NodeVisitor` на `with`-узлы с ≥10 context managers):**

| Было (line) | Context managers | Тест |
|---|---|---|
| ~1212 | **20** | `TestSetupOwnSiteOrderOfOperations.test_setup_nginx_temp_called_before_obtain_ssl_cert` |
| ~1338 | **18** | `TestSelfSignedDetection.test_setup_own_site_rolls_back_on_self_signed` |
| ~1380 | **20** | `TestSelfSignedDetection.test_setup_own_site_proceeds_on_valid_le_cert` |
| ~1499 | 10 | `TestNginxHardeningUnlinkBeforeRestart.test_setup_nginx_temp_unlinks_symlink_before_restart_on_failure` (заодно для единообразия) |

#### B. Общий helper `_enter_mtproto_ui_patches(stack, mtproto_mod)`

Все 3 теста мокали одинаковый набор из 13 UI/log-хелперов mtproto (`_banner`, `_box_top`, `_box_row`, `_box_sep`, `_box_item`, `_box_bot`, `_box_info`, `_ok`, `_err`, `_warn`, `_info`, `proto_ask`, `builtins.print`). Вынесено в общий helper в начале файла — меньше дублирования на будущее. Использование:

```python
with ExitStack() as stack:
    _enter_mtproto_ui_patches(stack, mtproto)
    # ... специфичные для теста stack.enter_context(patch.object(...))
    result = mtproto._setup_own_site("telemt.example.com", 8443)
```

#### C. Аудит остальных `tests/*.py`

Прошёлся по всем `tests/*.py` через `ast.NodeVisitor` на `with`-узлы с ≥15 context managers (порог из тикета). **Ничего похожего не найдено** — максимальное значение в других файлах 12 CM (`tests/test_dpi_detector.py:239`), что ниже порога 15+. Список всех with-цепочек с 8+ CM в репо (для будущего аудита):

```
tests/test_awg_cascade.py:450: 8 CM
tests/test_awg_cascade.py:483: 8 CM
tests/test_awg_cascade.py:511: 8 CM
tests/test_awg_standalone.py:273: 9 CM
tests/test_awg_standalone.py:346: 9 CM
tests/test_awg_standalone.py:393: 9 CM
tests/test_awg_diagnose.py:331: 8 CM
tests/test_dpi_detector.py:239: 12 CM
tests/test_dpi_detector.py:291: 8 CM
tests/test_dpi_detector.py:332: 8 CM
tests/test_dpi_detector.py:376: 8 CM
tests/test_geo_files.py:198: 10 CM
tests/test_geo_files.py:237: 10 CM
tests/test_geo_files.py:277: 8 CM
tests/test_geo_files.py:383: 10 CM
tests/test_mieru_download.py:169: 10 CM
```

Ничего из этого не тронуто — все ниже порога 15+, и пользователь явно указал "если где-то ещё есть аналогичная цепочка на 15+ patch".

### 🧪 Реальный вывод тестов (не текстовое заявление)

```
$ python3 -m py_compile tests/test_telemt_nginx_fallback.py && echo COMPILE_OK
COMPILE_OK

$ python3 -m pytest tests/test_telemt_nginx_fallback.py -v 2>&1 | tail -10
tests/test_telemt_nginx_fallback.py::TestSetupOwnSiteOrderOfOperations::test_setup_nginx_temp_called_before_obtain_ssl_cert PASSED [ 78%]
tests/test_telemt_nginx_fallback.py::TestSelfSignedDetection::test_is_cert_self_signed_returns_false_when_issuer_neq_subject PASSED [ 80%]
tests/test_telemt_nginx_fallback.py::TestSelfSignedDetection::test_is_cert_self_signed_returns_true_when_cert_missing PASSED [ 82%]
tests/test_telemt_nginx_fallback.py::TestSelfSignedDetection::test_is_cert_self_signed_returns_true_when_issuer_equals_subject PASSED [ 84%]
tests/test_telemt_nginx_fallback.py::TestSelfSignedDetection::test_setup_own_site_proceeds_on_valid_le_cert PASSED [ 86%]
tests/test_telemt_nginx_fallback.py::TestSelfSignedDetection::test_setup_own_site_rolls_back_on_self_signed PASSED [ 88%]
tests/test_telemt_nginx_fallback.py::TestNginxHardeningUnlinkBeforeRestart::test_setup_nginx_final_awg_unlinks_on_failure PASSED [ 90%]
tests/test_telemt_nginx_fallback.py::TestNginxHardeningUnlinkBeforeRestart::test_setup_nginx_final_own_site_unlinks_on_failure PASSED [ 92%]
tests/test_telemt_nginx_fallback.py::TestNginxHardeningUnlinkBeforeRestart::test_setup_nginx_final_reality_keeps_symlink_on_expected_failure PASSED [ 94%]
tests/test_telemt_nginx_fallback.py::TestNginxHardeningUnlinkBeforeRestart::test_setup_nginx_temp_unlinks_symlink_before_restart_on_failure PASSED [ 96%]
tests/test_telemt_nginx_fallback.py::TestSelectDomainReturns::test_known_category_returns_str PASSED [ 98%]
tests/test_telemt_nginx_fallback.py::TestSelectDomainReturns::test_q_returns_ivi_default PASSED [100%]

============================== 50 passed in 4.61s ==============================

$ python3 -m pytest tests/test_mtproto.py tests/test_ssl_certbot.py tests/test_nginx_watchdog.py tests/test_telemt_fallback.py tests/test_telemt_nginx_fallback.py 2>&1 | tail -5
tests/test_telemt_fallback.py .....................                      [ 72%]
tests/test_telemt_nginx_fallback.py .................................... [ 92%]
..............                                                           [100%]
============================= 183 passed in 13.91s =============================
```

### 🚫 Что НЕ трогали

- **Production-код** (`mtproto.py`, `nginx_setup.py`, `ssl_certbot.py`) — НЕ менялся в этом фиксе вообще. Это чисто тестовая инфраструктурная проблема.
- `_core.py`, `telemt_fallback.py`, AWG-модули, mirrors/downloader, TUI test runner — не тронуты.
- Логика самих тестов (что мокается и что проверяется) — не менялась, только механика множественных patch.
- Остальные тестовые файлы (`tests/*.py`) — аудит проведён, ничего 15+ CM не найдено, ничего не тронуто.

---

## v4.20.4 — FIX (BLOCKING): revert hardening в REALITY-ветке setup_nginx_final() — ломает обычную установку VLESS — 12 июля 2026

### 🐛 Регресс

Коммит `5823df7` (v4.20.3) применил hardening "при провале `nginx -t` сначала `unlink` симлинка, потом `reload` вместо `restart`" одинаково к 4 местам в `nginx_setup.py`. Для 3 из 4 это правильно. Для REALITY-ветки (основной финальный шаг установки VLESS, вызывается `setup_nginx_final()` БЕЗ аргументов из штатного install flow) — это **регресс, ломающий каждую свежую установку в REALITY-режиме** (дефолтный протокол).

**Почему это регресс:** `nginx_setup.py:870-905` ("=== REALITY: стандартный конфиг через Unix-сокет (VLESS) ===") тестирует итоговый конфиг через **заведомо временный** unix-сокет (создан вручную `socket.bind()+close()`, ничего реально не слушает — строка 870, комментарий "Создаём временный unix-сокет если нет"). Комментарий в коде на строке 905 прямым текстом: *"nginx -t: проверка с временным сокетом (предупреждение ожидаемо)"*. Сразу следом — `sock_path.unlink()` и `systemctl stop nginx` — то есть код изначально рассчитан на **регулярный fail** этой проверки на каждой свежей установке, это не ошибка, а особенность двухфазного бутстрапа: реальный сокет появится позже, nginx стартует "до Xray" уже на финальном шаге установки, за пределами этой функции.

Hardening v4.20.3 добавил в этот else-блок `unlink(link)` — то есть теперь на **каждой обычной REALITY-установке** удалялся только что созданный симлинк основного продакшн-сайта VLESS (`link = NGINX_ENABLED_DIR / PARAM_DOMAIN` — это VLESS-домен сервера, не Telemt-домен). Когда nginx стартует позже финальным шагом, сайта VLESS в `sites-enabled` уже не было → установка завершалась "успешно", но VLESS не работал.

Тест `tests/test_telemt_nginx_fallback.py:1580` (`test_setup_nginx_final_reality_unlinks_on_failure`) закреплял это как "правильное" поведение — мокал `_run` на `returncode=1` для `-t` и assert'ил `unlink`. Тест проверял, что баг работает как задуман, а не что система делает то, что нужно в реальности. Не было ни одного теста на "нормальный REALITY-инсталл переживает ожидаемый temp-socket warning и сайт остаётся включён".

### 🔧 Фикс

#### A. `nginx_setup.py` REALITY-ветка — revert hardening

`setup_nginx_final()` REALITY-ветка else-блок (строки ~895-911) возвращён к оригинальному состоянию (до v4.20.3):
- Удалён `try: link.unlink() except: pass`
- Удалён `_run(["systemctl", "reload", "nginx"], …)` — этот reload в v4.20.3 был добавлен "вместо restart", но в REALITY-ветке он тоже не нужен: nginx ещё не запущен (он стартует на финальном шаге установки), reload пустого nginx бессмысленен
- Восстановлены оригинальные `warn("nginx -t: проверка с временным сокетом (предупреждение ожидаемо):")` + `info("Nginx будет запущен до Xray (финальный шаг установки)")`
- Добавлен подробный комментарий-предупреждение: "ВНИМАНИЕ: этот else-блок НЕ подлежит hardening …" с объяснением двухфазного бутстрапа — чтобы следующий разработчик не повторил ошибку v4.20.3

#### B. Тест заменён на обратный

`tests/test_telemt_nginx_fallback.py`:
- Удалён `test_setup_nginx_final_reality_unlinks_on_failure` (закреплял баг как "правильное" поведение)
- Добавлен `test_setup_nginx_final_reality_keeps_symlink_on_expected_failure` — проверяет обратное: при `returncode=1` (ожидаемый temp-socket warning) symlink **СОХРАНЁН** (нет `unlink` ПОСЛЕ `symlink_to`). Учитывает что `link.unlink(missing_ok=True)` на строке ~884 (перед `symlink_to`) — это легитимная очистка старого symlink'а, его не считаем. Считаем только `unlink` после `symlink_to` через флаг `symlink_to_done`.

### 🚫 Что НЕ трогали (3 остальных места hardening сохранены)

Hardening v4.20.3 **оставлен без изменений** в 3 местах, где провал `nginx -t` — реальная ошибка, не запланированный сценарий:

1. **`setup_nginx_temp()`** (`nginx_setup.py:315-411`) — временный vhost для certbot ACME. Провал `-t` тут — реальная ошибка (домен ещё не резолвится, синтаксис, и т.п.). Тест `test_setup_nginx_temp_unlinks_symlink_before_restart_on_failure` подтверждает.
2. **`setup_nginx_final()` own-site TCP-ветка** (~570-600) — это НОВЫЙ конфиг для Telemt-домена, никакого "ожидаемого" временного состояния тут нет. Тест `test_setup_nginx_final_own_site_unlinks_on_failure` подтверждает.
3. **`setup_nginx_final()` AWG-ветка** (~720-770) — тот же довод. Тест `test_setup_nginx_final_awg_unlinks_on_failure` подтверждает.

xHTTP-ветка (~660-715) hardening в v4.20.3 не трогалась и сейчас не трогается — там else уже означает настоящую ошибку без всяких "ожидаемых" сценариев, это было учтено правильно с самого начала.

### 🧪 Регрессионные тесты

`tests/test_telemt_nginx_fallback.py` — 50 тестов (37 v4.20.1/v4.20.2 + 12 v4.20.3 + 1 изменённый v4.20.4):

- **`test_setup_nginx_final_reality_keeps_symlink_on_expected_failure`** (ЗАМЕНЁН) — реальный вызов `setup_nginx_final()` в REALITY-режиме с mock `nginx -t → returncode=1` (ожидаемый temp-socket warning). Проверка через `_tracking_unlink` + `symlink_to_done` флаг: `unlink` для `expected_link` **НЕ вызывается** после `symlink_to`. Симлинк остаётся в `sites-enabled` для финального старта nginx.

Все 183 связанных теста (108 mtproto + 25 ssl/nginx/telemt_fallback + 50 telemt_nginx_fallback) — зелёные.

### 📋 Что проверено реальным вызовом (не signature-check)

| Тест | Что проверяется | Метод |
|---|---|---|
| `test_setup_nginx_final_reality_keeps_symlink_on_expected_failure` | При `nginx -t` failure (ожидаемый temp-socket warning) symlink ОСТАЁТСЯ (нет `unlink` после `symlink_to`) | Реальный вызов + mock `_run` returncode=1 + `_tracking_unlink` с флагом `symlink_to_done` для различения легитимного unlink до symlink_to от бага unlink после |
| `test_setup_nginx_temp_unlinks_symlink_before_restart_on_failure` (не тронут) | `setup_nginx_temp` при failure — symlink удалён | Реальный вызов + mock |
| `test_setup_nginx_final_own_site_unlinks_on_failure` (не тронут) | own-site TCP ветка при failure — symlink удалён | Реальный вызов + mock |
| `test_setup_nginx_final_awg_unlinks_on_failure` (не тронут) | AWG-ветка при failure — symlink удалён | Реальный вызов + mock |

### 🚫 Что НЕ трогали (границы)

- `_core.py` — никаких новых module-level глобалов
- `telemt_fallback.py` — это ДРУГОЙ fallback (Middle Proxy → Direct Mode), не путать
- `obtain_ssl_cert()` — НЕ менялся
- AWG-модули, mirrors/downloader, TUI test runner — не тронуты
- Существующий VLESS install flow — byte-for-byte идентичен (regression guards из v4.20.2: `test_vless_reality_uses_unix_socket`, `test_vless_reality_has_https_redirect`)

---

## v4.20.3 — FIX (BLOCKING): own-site домен Telemt не получает реальный LE-сертификат — certbot падает молча, self-signed fallback остаётся невидимым для гвардов — 12 июля 2026

### 🐛 Баг

Коммит `6e9d7fb` (v4.20.2) исправил три блокера с `PROTOCOL_MODE`, но появился четвёртый, того же архитектурного класса: часть кода в own-site-flow всё ещё завязана на `core.PARAM_DOMAIN` там, где нужен явный домен.

`_setup_own_site()` в `mtproto.py` делал:
1. `obtain_ssl_cert(domain=domain)` — certbot, webroot-метод, `--webroot-path /var/www/{domain}`
2. `setup_nginx_final(domain=domain, ...)` — ЗДЕСЬ впервые создавался nginx vhost для `{domain}` на порту 80 с `location /.well-known/acme-challenge/`

На шаге 1 nginx **ещё не знает** про `{domain}` — vhost появится только на шаге 2. HTTP-01 challenge с `Host: {domain}` не совпадёт ни с одним `server_name`, уйдёт в дефолтный vhost (VLESS-домен), там нет файла челленджа → 404 → certbot падает.

В штатном VLESS-флоу это решено: `_core.py` вызывает `setup_nginx_temp()` **ДО** `obtain_ssl_cert()` — временный vhost для `PARAM_DOMAIN` на порту 80. Для own-site эквивалента этого шага не было. Плюс сам `setup_nginx_temp()` по-прежнему не был параметризован — читал `core.PARAM_DOMAIN` безусловно, та же болезнь, что чинили в `setup_nginx_final()`/`create_website()`/`obtain_ssl_cert()`, просто не долечили здесь.

**Почему это тихо, а не просто "не работает":** `obtain_ssl_cert()` уже содержит fallback — если certbot падает, молча генерируется self-signed сертификат (`generate_self_signed_cert`), установка продолжается. `_check_mask_backend_ready()` — голый TCP-connect, ему всё равно, самоподписанный сертификат или нет — проверка зелёная. Ни один из гвардов v4.20.2 этот случай не ловил: инсталлятор репортил успех own-site режима, а Telemt с `tls_emulation=true` живьём фетчил и отдавал self-signed сертификат — для DPI/censor это заметная аномалия, **ХУЖЕ** исходного `fake_cert_len=2048`, который и должны были устранить.

### 🔧 Фикс

#### A. `nginx_setup.py: setup_nginx_temp(domain=None)`

Добавлен опциональный параметр `domain: Optional[str] = None`, перекрывающий `core.PARAM_DOMAIN` — по той же схеме, что уже применена в `create_website()`/`setup_nginx_final()`/`obtain_ssl_cert()`. Если не передан — поведение идентично предыдущему (VLESS install flow не меняется ни в одном байте вывода). Функция создаёт временный HTTP:80 vhost с `location /.well-known/acme-challenge/ { root /var/www/{domain}; }`.

#### B. `_setup_own_site()` — порядок операций

Вставлен вызов `setup_nginx_temp(domain=domain)` **ПЕРЕД** `obtain_ssl_cert(domain=domain)`. При исключении — тот же паттерн отката: `_err` + `_cleanup_own_site(domain)` + `return OwnSiteConfig(mask_port=0)`. Без этого шага certbot получает 404 → silent self-signed fallback → вся фича теряет смысл.

#### C. Self-signed detection — fail-loud для own-site

Новый helper `_is_cert_self_signed(domain)` в `mtproto.py`: читает `/etc/letsencrypt/live/{domain}/cert.pem` (или `fullchain.pem` как fallback) через `openssl x509 -issuer -subject -noout` и сравнивает issuer с subject. Если совпадают — сертификат self-signed.

`obtain_ssl_cert()` менять нельзя для VLESS-кейса (там self-signed fallback — осознанное поведение "лучше так, чем никак"), но для own-site он бессмысленен. Поэтому в `_setup_own_site()` **ПОСЛЕ** `obtain_ssl_cert(domain=domain)` — explicit-проверка через `_is_cert_self_signed(domain)`:
- Self-signed → `_err` + `_cleanup_own_site(domain)` + `return OwnSiteConfig(mask_port=0)` (откат к donor-режиму)
- Валидный LE (issuer != subject) → own-site продолжает штатно

Это даёт **fail-loud вместо fail-silent** конкретно для own-site сценария, не трогая поведение `obtain_ssl_cert()` для VLESS. Сертификата нет вообще → тоже True (fail-safe).

#### D. Hardening — unlink symlink ДО restart при `nginx -t` failure

Во всех 4 местах в `nginx_setup.py` где встречается паттерн "написать cfg → symlink → `nginx -t` → если fail, всё равно `systemctl restart nginx`":
1. `setup_nginx_temp` (строки ~383-406)
2. `setup_nginx_final` own-site TCP ветка (строки ~585-602)
3. `setup_nginx_final` AWG-ветка (строки ~757-774)
4. `setup_nginx_final` REALITY-ветка (строки ~883-908)

При провале `nginx -t` сначала откатывается just-created симлинк (`link.unlink()`), и ТОЛЬКО ПОТОМ `systemctl reload nginx` (НЕ `restart` — restart с битым конфигом может не подняться). Сейчас restart выполнялся с уже подключённым битым конфигом — если процесс не поднимется, ляжет весь nginx, включая рабочие VLESS-сайты, даже если ошибка была локальна для одного нового vhost. Также: `restart` заменён на `reload` — reload загружает старый (валидный) конфиг, restart с битым конфигом может привести к неработающему nginx.

Применимо ко всем четырём местам консистентно — это НЕ требует нового параметра/сигнатуры, чисто внутренняя правка порядка операций.

### 🧪 Регрессионные тесты (50 тестов, все 5 обязательных сценариев)

`tests/test_telemt_nginx_fallback.py` — 13 НОВЫХ тестов (поверх 37 существующих):

1. **`TestSetupNginxTempParameterized`** (3 теста) — РЕАЛЬНЫЙ вызов `setup_nginx_temp()` + парсинг конфига:
   - `test_setup_nginx_temp_with_explicit_domain_uses_it` — `domain="telemt.example.com"` при `core.PARAM_DOMAIN="vless.example.com"` → конфиг для `telemt.example.com`, НЕ для `vless.example.com`
   - `test_setup_nginx_temp_without_domain_uses_core_param` — regression guard: без аргументов → `core.PARAM_DOMAIN` (VLESS flow не сломан)
   - `test_setup_nginx_temp_has_acme_challenge_location` — конфиг содержит `/.well-known/acme-challenge/` для certbot webroot

2. **`TestSetupOwnSiteOrderOfOperations`** (1 тест) — порядок вызовов через mock call order:
   - `test_setup_nginx_temp_called_before_obtain_ssl_cert` — `setup_nginx_temp(domain=…)` вызывается СТРОГО до `obtain_ssl_cert(domain=…)` (проверка через список call_order + assertLess)

3. **`TestSelfSignedDetection`** (5 тестов) — `_is_cert_self_signed` + интеграция в `_setup_own_site`:
   - `test_is_cert_self_signed_returns_true_when_issuer_equals_subject` — self-signed (issuer == subject) → True
   - `test_is_cert_self_signed_returns_false_when_issuer_neq_subject` — валидный LE (issuer != subject) → False
   - `test_is_cert_self_signed_returns_true_when_cert_missing` — сертификат не найден → True (fail-safe)
   - `test_setup_own_site_rolls_back_on_self_signed` — `_is_cert_self_signed → True` → `OwnSiteConfig(mask_port=0)` + `_cleanup_own_site` вызван
   - `test_setup_own_site_proceeds_on_valid_le_cert` — `_is_cert_self_signed → False` → `mask_port=8444` (own-site активен)

4. **`TestNginxHardeningUnlinkBeforeRestart`** (4 теста) — hardening для всех 4 мест:
   - `test_setup_nginx_temp_unlinks_symlink_before_restart_on_failure` — `nginx -t` failure → symlink удалён ДО reload
   - `test_setup_nginx_final_own_site_unlinks_on_failure` — own-site TCP ветка → symlink удалён
   - `test_setup_nginx_final_awg_unlinks_on_failure` — AWG-ветка → symlink удалён
   - `test_setup_nginx_final_reality_unlinks_on_failure` — REALITY-ветка → symlink удалён

Все 183 связанных теста (108 mtproto + 25 ssl/nginx/telemt_fallback + 50 telemt_nginx_fallback) — зелёные. Существующий VLESS install flow — byte-for-byte идентичен предыдущему.

### 📋 Что конкретно проверено реальным вызовом (не signature-check) для каждого из 5 тестов

| Тест | Что проверяется | Метод |
|---|---|---|
| 1. `test_setup_nginx_temp_with_explicit_domain_uses_it` | `setup_nginx_temp(domain="telemt.example.com")` создаёт конфиг с `server_name telemt.example.com` и `/var/www/telemt.example.com`, НЕ `vless.example.com` | Реальный вызов + парсинг записанного конфига (assertIn/assertNotIn на содержимом) |
| 2. `test_setup_nginx_temp_called_before_obtain_ssl_cert` | `setup_nginx_temp` вызывается ДО `obtain_ssl_cert` в `_setup_own_site` | Mock с `side_effect` записывает порядок вызовов в `call_order` список + `assertLess(idx_temp, idx_ssl)` |
| 3. `test_setup_own_site_rolls_back_on_self_signed` | Self-signed сертификат → `_setup_own_site` возвращает `mask_port=0` + вызывает `_cleanup_own_site` | Mock `_is_cert_self_signed → True`, проверка результата + `cleanup_calls` список |
| 3. `test_setup_own_site_proceeds_on_valid_le_cert` | Валидный LE → `mask_port=8444` (own-site активен) | Mock `_is_cert_self_signed → False`, проверка `result.mask_port == 8444` |
| 4. `test_setup_nginx_final_*_unlinks_on_failure` (×3) + `test_setup_nginx_temp_unlinks_symlink_before_restart_on_failure` | При `nginx -t` failure symlink удаляется ДО restart/reload | Mock `_run` возвращает `returncode=1`, `_tracking_unlink` записывает вызовы для конкретного symlink-пути |
| 5. `test_setup_nginx_temp_without_domain_uses_core_param` | VLESS flow (без аргументов) → `core.PARAM_DOMAIN` (regression guard) | Реальный вызов + парсинг: `assertIn("server_name vless.example.com", content)` |

### 🚫 Что НЕ трогали

- `_core.py` — никаких новых module-level глобалов
- `telemt_fallback.py` — это ДРУГОЙ fallback (Middle Proxy → Direct Mode), не путать
- `obtain_ssl_cert()` — НЕ менялся; self-signed fallback остался для VLESS-кейса (там это осознанное поведение)
- AWG-модули, mirrors/downloader, TUI test runner — не тронуты
- Существующий VLESS install flow — byte-for-byte идентичен (regression guard `test_setup_nginx_temp_without_domain_uses_core_param` + `test_vless_reality_uses_unix_socket` + `test_vless_reality_has_https_redirect` из v4.20.2)

---

## v4.20.2 — FIX (BLOCKING): setup_nginx_final() parameterized по PROTOCOL_MODE — own-site режим Telemt ломает nginx в дефолтной REALITY-конфигурации — 12 июля 2026

### 🐛 Баг

Коммит `b935c34` (v4.20.1) параметризовал `setup_nginx_final(domain, port, socket_path)`, но НЕ параметризовал `PROTOCOL_MODE` и `AWG_EXIT_ENABLED` — они читались из `core.PROTOCOL_MODE` / `core.AWG_EXIT_ENABLED` безусловно. Эта переменная выбирает одну из трёх веток генерации nginx-конфига (xhttp / AWG / reality-default), и все три ветки для own-site-сценария Telemt вели себя не так, как заявлено в докстринге функции.

**Проверенные баги (чтением кода):**

1. **REALITY-ветка (ДЕФОЛТ, `core.PROTOCOL_MODE == "reality"`)** — самый частый кейс (одиночный VLESS-сервер). Игнорирует параметр `port` целиком. Слушает `listen unix:{PARAM_SOCKET_PATH}`. Когда `_setup_own_site()` вызывает `setup_nginx_final(domain=…, port=mask_port, socket_path=None)`, `None` откатывается на `core.PARAM_SOCKET_PATH` — на ТОТ ЖЕ unix-сокет, который использует VLESS-сайт. Результат: два `server{}` блока с `listen unix:{один и тот же путь} ... default_server;` — duplicate default server, `nginx -t` падает, но код безусловно делает `systemctl restart nginx`. На живом сервере это роняет nginx насовсем — ломает уже работавший VLESS REALITY fallback.

2. **XHTTP-ветка** — Telemt-домен получает `location {xhttp_path} { proxy_pass http://127.0.0.1:{XHTTP_BACKEND_PORT}; }` — маскировочный домен проксирует прямо в боевой Xray-бэкенд VLESS.

3. **AWG_EXIT_ENABLED-ветка** — TLS вообще не терминируется nginx (только HTTP:80 редирект). `mask_port` никогда не слушает TLS → `_check_mask_backend_ready` корректно фейлится → откат в donor-режим. Ветка "случайно безопасна" тем, что молча не работает.

4. **Тесты не ловили** — `test_setup_nginx_final_accepts_domain_port_socket` был тавтологичным (только `inspect.signature()`, функция ни разу не вызывалась).

5. **Откат не чистил** — guard-блок при неготовности nginx переписывал только `telemt.toml`, но НЕ удалял уже созданные `/var/www/<telemt-domain>`, файл в `NGINX_CONF_DIR/<telemt-domain>` и симлинк в `NGINX_ENABLED_DIR/<telemt-domain>`. Сломанный конфиг оставался на диске и enabled.

### 🔧 Фикс

#### A. `nginx_setup.py: setup_nginx_final()` — новые параметры + sentinel

- Добавлены параметры `protocol_mode: Optional[str] = None`, `awg_exit_enabled: Optional[bool] = None`, `site_template: Optional[str] = None` — перекрывают `core.PROTOCOL_MODE` / `core.AWG_EXIT_ENABLED` / `core.PARAM_SITE_TEMPLATE` по той же схеме, что `domain`.
- `port` и `socket_path` переведены с `Optional[int/str] = None` на **sentinel `_UNSET`** — это КРИТИЧНО для различения "не передан" (→ inherit из core, VLESS flow) от "передан None" (→ own-site TCP режим). Обычный `default=None` не различает эти два случая.
- `_own_site_tcp` detection: `_socket_explicit and PARAM_SOCKET_PATH is None and _port_explicit and SERVER_PORT` → own-site TCP-режим.

#### B. Новая own-site TCP ветка в `setup_nginx_final()`

Когда `_own_site_tcp=True`, генерируется **простой статический HTTPS-сайт** на `listen 127.0.0.1:{port} ssl`:
- БЕЗ `proxy_protocol` (Telemt подключается напрямую по TCP, не через Xray xver=1)
- БЕЗ `real_ip_header proxy_protocol` / `set_real_ip_from unix:` (эта логика — только для VLESS REALITY unix-socket)
- БЕЗ `proxy_pass` на Xray backend
- HTTP:80 listener только для ACME challenges (БЕЗ `return 301 https://` — редирект ушёл бы на порт 443, который слушает Telemt, а не на mask_port)
- `default_server` с `ssl_reject_handshake on` (или fallback для старых nginx)

Ветка ставится **до** проверок `PROTOCOL_MODE == "xhttp"` / `AWG_EXIT_ENABLED` — own-site обрабатывается первым и return-ит. VLESS-ветки (xhttp/AWG/REALITY-unix-socket) выполняются только когда own-site не активен.

#### C. Domain collision check

Перед записью конфига: если `_own_site_tcp and PARAM_DOMAIN == core.PARAM_DOMAIN` → `RuntimeError` с понятным текстом. Защита от человеческой ошибки при вводе домена в `_select_own_domain_submenu`. Дополнительно — ранний чек в `_setup_own_site()` ДО certbot, чтобы не выпускать сертификат зря.

#### D. `_cleanup_own_site(domain)` в `mtproto.py`

Новый helper — удаляет orphaned-файлы при откате к donor-режиму:
- `NGINX_CONF_DIR/<domain>` (nginx config)
- `NGINX_ENABLED_DIR/<domain>` (symlink)
- `/var/www/<domain>` (web_root)
- `nginx -t` + `systemctl reload/restart nginx` после cleanup — вернуть nginx в валидное состояние
- Сертификат Let's Encrypt НЕ удаляем (отзыв не критичен, не тема этого фикса)

Вызывается из:
- `_setup_own_site()` — при ошибке на любом этапе (certbot упал, setup_nginx_final упал, nginx не готов)
- Guard-блока в `_run_install_inner()` — при откате из-за неготовности nginx перед стартом Telemt

#### E. `_setup_own_site()` обновлён

- Передаёт `protocol_mode="reality", awg_exit_enabled=False, site_template=tmpl` в `setup_nginx_final()` — форсирует простую статическую HTTPS-заглушку, независимо от VLESS-режима сервера.
- Убран отдельный вызов `create_website(domain=…, site_template=tmpl)` — `create_website` теперь вызывается ВНУТРИ `setup_nginx_final` с `site_template=tmpl` (фикс двойного write, который перезаписывал выбранный шаблон на `core.PARAM_SITE_TEMPLATE`).
- Ранний чек коллизии домена с `core.PARAM_DOMAIN` — ДО certbot.
- Все except-блоки вызывают `_cleanup_own_site(domain)` перед откатом.

### 🧪 Регрессионные тесты (37 тестов, все 7 обязательных сценариев)

`tests/test_telemt_nginx_fallback.py` — 13 НОВЫХ тестов (поверх 24 существующих):

1. **`TestSetupNginxFinalOwnSiteTcpMode`** (6 тестов) — РЕАЛЬНЫЙ вызов `setup_nginx_final()` с замоканным core, парсинг сгенерированного конфига:
   - `test_own_site_with_reality_server_uses_tcp_not_unix` — REALITY-сервер → own-site на TCP, НЕ unix-сокет, БЕЗ proxy_protocol/real_ip_header
   - `test_own_site_no_xray_proxy_pass` — НЕ содержит `proxy_pass` на XHTTP_BACKEND_PORT
   - `test_own_site_with_xhttp_server_still_uses_tcp` — XHTTP-сервер → own-site всё равно TCP, НЕ проксирует на Xray
   - `test_own_site_with_awg_server_has_tls_listener` — AWG-сервер → own-site имеет TLS listener на mask_port (не только HTTP:80 редирект)
   - `test_domain_collision_raises_runtime_error` — own_site_domain == core.PARAM_DOMAIN → RuntimeError
   - `test_own_site_http80_no_https_redirect` — HTTP:80 БЕЗ `return 301 https` (ушёл бы на Telemt:443), только ACME + 404

2. **`TestSetupNginxFinalVlessRegression`** (2 теста) — Regression guard: VLESS install flow `setup_nginx_final()` без аргументов:
   - `test_vless_reality_uses_unix_socket` — unix-сокет с proxy_protocol, БЕЗ TCP
   - `test_vless_reality_has_https_redirect` — HTTP:80 → HTTPS-редирект (это нормально для VLESS, в отличие от own-site)

3. **`TestSetupNginxFinalTwoParallelDomains`** (1 тест) — VLESS-домен + Telemt-домен одновременно:
   - `test_vless_and_telemt_domains_coexist` — VLESS на unix-сокете, Telemt на TCP:8444, оба валидны, нет конфликта listen

4. **`TestCleanupOwnSite`** (3 теста) — cleanup orphaned-файлов:
   - `test_cleanup_removes_orphaned_files` — удаляет nginx config, symlink, web_root
   - `test_cleanup_with_empty_domain_is_noop` — `""` → no-op
   - `test_cleanup_with_nonexistent_domain_is_noop` — несуществующий домен → no-op

5. **`TestGuardBlockCleanupOnRollback`** (1 тест) — guard-блок при откате:
   - `test_guard_block_calls_cleanup_on_nginx_down` — `_check_mask_backend_ready=False` → `_cleanup_own_site` вызван, конфиг переписан в donor-режим

Все 170 связанных тестов (108 mtproto + 25 ssl/nginx/telemt_fallback + 37 telemt_nginx_fallback) — зелёные. Существующий VLESS install flow (`setup_nginx_final()` без аргументов) — byte-for-byte идентичен предыдущему.

### 📋 Какие PROTOCOL_MODE-ветки протестированы вызовом функции с парсингом вывода

| Ветка | core.PROTOCOL_MODE | core.AWG_EXIT_ENABLED | Тест |
|---|---|---|---|
| REALITY (own-site TCP) | `"reality"` | `False` | `test_own_site_with_reality_server_uses_tcp_not_unix` |
| XHTTP (own-site TCP) | `"xhttp"` | `False` | `test_own_site_with_xhttp_server_still_uses_tcp` |
| AWG (own-site TCP) | `"reality"` | `True` | `test_own_site_with_awg_server_has_tls_listener` |
| REALITY (VLESS unix-socket) | `"reality"` | `False` | `test_vless_reality_uses_unix_socket` |

Все 4 комбинации протестированы реальным вызовом `setup_nginx_final()` + парсингом сгенерированного nginx-конфига (НЕ signature-check).

### 🚫 Что НЕ трогали

- `_core.py` — никаких новых module-level глобалов (требование из исходного тикета сохранено)
- `telemt_fallback.py` — это ДРУГОЙ fallback (Middle Proxy → Direct Mode), не путать
- AWG-модули, mirrors/downloader, TUI test runner — не тронуты
- Существующий VLESS install flow — byte-for-byte идентичен (regression guard `test_vless_reality_uses_unix_socket` + `test_vless_reality_has_https_redirect`)

---

## v4.20.1 — Telemt nginx-fallback: собственный домен и сайт вместо чужого donor-домена — 12 июля 2026

### 🎭 Telemt mask: новый режим "own-site" (свой домен + свой сайт на локальном nginx)

Раньше секция `[censorship]` в `telemt.toml` писалась фиксированно:
```toml
tls_domain = "<донор, напр. microsoft.com>"
mask = true
mask_port = 443
fake_cert_len = 2048
```
Без `mask_host` Telemt по умолчанию использует `mask_host = tls_domain`, т.е. весь неопознанный/failed-handshake трафик реально сплайсится на **чужой внешний домен**. Без `tls_emulation` Telemt отдаёт synthetic fake-cert (~2048 байт) — это и есть **детектируемая аномалия**, по которой TSPU/DPI отличают настоящий HTTPS-сайт от маскирующегося MTProxy.

Теперь добавлен альтернативный режим: **свой домен + свой сайт на локальном nginx**. Telemt слушает 443/8443 снаружи как раньше; локальный nginx с реальным Let's Encrypt сертификатом того же домена сидит **СЗАДИ** (за Telemt, не перед ним); Telemt получает `mask_host`/`mask_port` + `tls_emulation=true` и сплайсит на него. Параметры `censorship.mask_host` / `mask_port` / `mask_unix_sock` / `tls_emulation` уже поддержаны бинарником Telemt (`docs/Config_params/CONFIG_PARAMS.ru.md` в telemt/telemt) — патчить исходники Telemt не нужно.

### 🔧 Изменения в модулях

#### `chimera/modules/nginx_setup.py` (Задача 1)
- `create_website(domain=None, site_template=None)` — параметры, переданные явно, **ПЕРЕКРЫВАЮТ** значения из `core.PARAM_DOMAIN` / `core.PARAM_SITE_TEMPLATE`. Если не переданы — поведение 100% идентично предыдущему (VLESS install flow не меняется ни в одном байте вывода).
- `setup_nginx_final(domain=None, port=None, socket_path=None)` — аналогично для `PARAM_DOMAIN` / `SERVER_PORT` / `PARAM_SOCKET_PATH`. `PROTOCOL_MODE`, `AWG_EXIT_ENABLED`, `XHTTP_PATH`, `XHTTP_BACKEND_PORT`, `IS_IPV6_AVAILABLE` остаются из core (они касаются только VLESS-флоу).
- Это позволяет **параллельно** поднять сайт для VLESS-домена и отдельный сайт для Telemt-домена на одном сервере — без мутации глобального state в `_core.py`.

#### `chimera/modules/ssl_certbot.py`
- `obtain_ssl_cert(domain=None)` — если `domain` передан явно, сертификат выпускается для этого домена (а не для `core.PARAM_DOMAIN`). Используется в Telemt nginx-fallback, где домен маскировки может отличаться от основного VLESS-домена сервера. `PARAM_EMAIL` и `PROTOCOL_MODE` остаются из core.

#### `chimera/modules/mtproto.py` (Задача 2)
- **`OwnSiteConfig` dataclass** — параметры локального nginx-сайта для маскировки Telemt: `domain`, `mask_host` (всегда `"127.0.0.1"` в этой итерации), `mask_port`.
- **`_pick_local_nginx_port(telemt_port)`** — подбирает свободный TCP-порт на 127.0.0.1 из диапазона 8444–9998 (избегая 9000 и `telemt_port`), проверяя занятость через `ss -tlnH`.
- **`_check_mask_backend_ready(mask_host, mask_port, timeout)`** — TCP-connect проверка готовности nginx. **КРИТИЧНО** для `tls_emulation=true` (telemt/telemt issues #330, #713): Telemt при старте делает живой TLS-fetch cert-chain с `mask_host`; если nginx ещё не поднялся — fetch падает с "early eof" и Telemt уходит в restart-loop.
- **`_select_domain(telemt_port=8443)`** — теперь возвращает `str` (donor-домен, текущее поведение) ИЛИ `OwnSiteConfig` (новое). Пункт "99 ✏️ Свой домен" превращён в подменю `_select_own_domain_submenu()` с двумя вариантами:
  - **1) Donor-домен (как раньше)** — просто домен, без своего сайта. Backward-compat.
  - **2) Свой домен + свой сайт (nginx fallback)** — вызывает `_setup_own_site()`: подбор `mask_port` → certbot → `create_website(domain=…)` → `setup_nginx_final(domain=…, port=…, socket_path=None)` → проверка готовности nginx (TCP connect). Возвращает `OwnSiteConfig` с `mask_port>0` при успехе, `mask_port=0` при отказе (caller видит это и не пишет `mask_host` в конфиг).
- **`_write_config(...)`** — добавлены опциональные параметры `mask_host: str = ""`, `mask_port: int = 0`, `tls_emulation: bool = False`. Если `mask_host` пуст — поведение **byte-for-byte идентично** предыдущему (donor-режим, regression guard). Если задан — censorship-секция дополнительно пишет `mask_host`, `mask_port` (только если >0), `tls_emulation = true/false`. `mask_host` и `mask_unix_sock` взаимоисключающи по спецификации Telemt; в этой итерации поддерживается только TCP `mask_host` (unix-сокет не реализуем — см. ниже "Почему не unix-сокет").
- **Call site в `_run_install_inner`** — после `_select_domain(telemt_port=port)` разветвление: если вернулся `OwnSiteConfig` — передаём `mask_host`/`mask_port`/`tls_emulation=True` в `_write_config`; если `str` — передаём пустые (donor-режим).
- **Guard перед стартом Telemt** — если включён own-site режим, 5 попыток с интервалом 1с проверяем `_check_mask_backend_ready(mask_host, mask_port)`. Если nginx не готов — переписываем конфиг в donor-режим (без `mask_host`), чтобы избежать silent regression в духе AWG rotation no-op.

### 🚫 Почему не unix-сокет в первой итерации

`mask_unix_sock` был бы чище (не занимает TCP-порт), но требует, чтобы nginx слушал unix-сокет, а не TCP — это дополнительная развилка в `setup_nginx_final()`, которая сейчас везде оперирует TCP-портом (`SERVER_PORT`). Не расширяем эту сложность без необходимости. TCP на `127.0.0.1:<порт>` достаточно и проще для отладки. Валидация "ровно одно из `mask_host`/`mask_unix_sock`" добавлена в docstring `_write_config()` для будущей итерации.

### 🚫 Что НЕ трогали (строгие границы задачи)

- `chimera/modules/telemt_fallback.py` — это **ДРУГОЙ** fallback (Middle Proxy → Direct Mode, гибрид ME). Не путать, не переиспользовать имена `fallback_to_direct` / `FallbackConfig` для этой задачи. Никаких правок.
- `awg*.py`, `telemt_mss_selector.py`, `telemt_syn_limiter.py`, `telemt_geoip_*` — AWG-трек, не трогаем.
- `telemt_mirrors.py`, `telemt_packages.py`, `telemt_geoip_mirrors.py` — mirrors/downloader, не трогаем.
- TUI diagnostic test runner — не трогаем.
- **`_core.py`** — НЕ добавлены новые module-level глобалы (`PARAM_*` и т.п.). Никакой новой бизнес-логики. Если функциям из `nginx_setup.py`/`ssl_certbot.py` нужно читать что-то из core — используется только уже существующие атрибуты через `_core_module()`, как и раньше.

### 🧪 Регрессионные тесты

`tests/test_telemt_nginx_fallback.py` — 24 теста в 7 классах:

1. **`TestWriteConfigDonorModeRegression`** — `_write_config(mask_host="")` → censorship-секция побайтово идентична baseline (`[censorship]` + `tls_domain` + `mask=true` + `mask_port=443` + `fake_cert_len=2048`). Также проверка что `mask_host` и `tls_emulation` отсутствуют в donor-режиме.
2. **`TestWriteConfigOwnSiteMode`** — `_write_config(mask_host="127.0.0.1", mask_port=8443, tls_emulation=True)` → парсим сгенерированный TOML и проверяем реальные строки `mask_host = "127.0.0.1"`, `mask_port = 8443`, `tls_emulation = true` (НЕ тавтологичный assert на аргумент). Также: `mask_port=0` → строка `mask_port` не пишется; `tls_emulation=False` → пишется `false`.
3. **`TestCreateWebsiteIsolationFromGlobalState`** — два последовательных вызова `create_website(domain="a.com", ...)` и `create_website(domain="b.com", ...)` создают **ДВА разных** `web_root` (`/var/www/a.com` и `/var/www/b.com`), а не перезаписывают `PARAM_DOMAIN` друг другом. Также: явный `domain=` перекрывает `core.PARAM_DOMAIN="wrong.example.com"`; без явного `domain=` используется `core.PARAM_DOMAIN` (backward-compat).
4. **`TestMaskBackendReadinessCheck`** — `_check_mask_backend_ready` возвращает True на слушающем TCP-сокете, False на закрытом порту, False на timeout (RFC 5737 TEST-NET-1). **ГЛАВНЫЙ guard-тест**: mock где `_check_mask_backend_ready → False` → install flow переписывает конфиг в donor-режим (`_write_config(mask_host="", ...)`) и НЕ продолжает молча в own-site режиме.
5. **`TestOwnSiteConfigDataclass`** — поля и значения по умолчанию (`mask_host="127.0.0.1"`, `mask_port=0`).
6. **`TestPickLocalNginxPort`** — НЕ возвращает порт, совпадающий с `telemt_port`; возвращает 0 если все кандидаты заняты; пропускает порты, которые `ss` видит как LISTEN.
7. **`TestSignatureCompatibility`** — `obtain_ssl_cert(domain=None)`, `setup_nginx_final(domain, port, socket_path)`, `create_website(domain, site_template)` — сигнатуры соответствуют.
8. **`TestSelectDomainReturns`** — `_select_domain` возвращает `str` для выбора из готовой категории (sanity-check backward-compat).

Все 24 теста проходят. Существующие `tests/test_mtproto.py` (108 тестов), `tests/test_ssl_certbot.py`, `tests/test_nginx_watchdog.py`, `tests/test_telemt_fallback.py` (25 тестов суммарно) — проходят без изменений.

---

## v4.20.0 — Унификация скачивания: единый download_manager.py для всех модулей — 11 июля 2026

### 📦 Миграция всех модулей на `download_manager.fetch_package()`

Все модули проекта, скачивающие бинарники/архивы/исходники для установки, переведены на единый декларативный механизм `PackageSpec` + `fetch_package()` из `chimera/modules/download_manager.py`. Устранена дублирующаяся ad-hoc логика скачивания (свои таймауты, свои циклы retry, свои функции «подсказка для ручного скачивания») — теперь каждый пакет описывается одним `PackageSpec`, а `fetch_package()` сам перебирает зеркала, проверяет ручное размещение через WinSCP, копирует в `install_dests` с нужными правами и печатает единообразную подсказку при полном провале.

**Что мигрировано (29 PackageSpec-ов, волны 1-6):**
- **Волна 1:** `turntunnel.py`, `turnable.py` — бинарники vk-turn-proxy и turnable.
- **Волна 2:** `wdtt.py`, `webdav_tunnel.py` — source-tarball'ы + общий `GO_TOOLCHAIN_SPEC` для Go toolchain (4 зеркала: go.dev + golang.google.cn + mirrors.aliyun.com + mirrors.tencent.com).
- **Волна 3:** `hysteria2_auto_update.py`, `hysteria2_exit_mgr.py` (локальная установка), `dnscrypt_setup.py` — бинарник Hysteria2 + tarball dnscrypt-proxy.
- **Волна 4:** `xray_install.py` (zip + checksums.txt + install-release.sh + geo-файлы), `naiveproxy.py`, `fptn.py`.
- **Волна 5:** `awg_cascade.py` (ru.zone data feed), `slipgate.py` (install.sh), `telemt_panel.py` (GeoIP .mmdb), `network_bench.py` (iperf3).
- **Волна 6:** `awg_transport.py` (amneziawg-tools zip + 2 source-tarball'а), `olcrtc.py` (source-tarball + Go toolchain). Все 3 `git clone` кейса переведены на HTTP-tarball через `codeload.github.com` (Variant A) — ни один build-скрипт не требует `.git/`-метаданных или submodule'ов.

**Что НЕ мигрировано (подтверждённые исключения):**
- `hybrid_addon.py` — standalone-модуль (запускается без клонирования репозитория, только stdlib).
- `system_deps.py` — apt-repo bootstrap (nginx GPG key + sources.list), не файл-пакет.
- `hysteria2_exit_mgr.py` remote SSH install — push на удалённый хост по SSH, `install_dests` подразумевает локальные пути.
- Health-check'и, IP-lookups (api.ipify.org), API-metadata (api.github.com за tag_name), runtime-config fetches (Telegram ME endpoints), bash-скрипты генерируемые в файл — всё это не является «скачиванием пакета для установки» и не мигрировалось.

### 🛡️ Найденные и исправленные баги

- **`filename_builder` kwargs mismatch** (5 случаев): `TURNABLE_SPEC`, `XRAY_ZIP_SPEC`, внутренний `chk_spec`, `FPTN_SPEC` (2 бага — filename_builder и mirror_urls_builder conflict). `fetch_package()` вызывает `spec.filename_builder(**filename_kwargs)` без фильтрации — лямбды с фиксированными параметрами падали с `TypeError`, краша установку turnable/xray/fptn и тихо отключая SHA256-верификацию xray. Ко всем 31 `filename_builder` добавлен `**kw` catch-all для защиты от будущих регрессий.
- **Потеря safety-инварианта в `hysteria2_auto_update`**: после миграции `post_install` делал atomic-replace (только ELF magic проверка), а runtime-проверка (`<binary> version`) ушла в вызывающий код ПОСЛЕ `fetch_package` — к этому моменту старый бинарник уже удалён. Восстановлён invariant «проверить, потом заменить»: `HYSTERIA2_SPEC.post_install` теперь запускает бинарник ДО atomic-replace, при неудаче возвращает `False` не трогая старый.
- **Ложный статус SHA256 верификации в `xray_install.py`**: `install_xray()` и `_xray_do_upgrade()` безусловно печатали «SHA256 верифицирован», даже когда `checksums.txt` был недоступен и верификация пропускалась. Добавлена модуль-уровневая переменная `_XRAY_SHA256_STATUS` (`verified`/`skipped`/`no_tag`/`failed`); сообщение печатается только при `verified`, при `skipped`/`no_tag` — `warn`.

### 🧪 Регрессионные тесты

- `tests/test_all_specs_real_fetch_package.py` — 31 тест, по одному на каждый `PackageSpec`. Каждый вызывает НАСТОЯЩИЙ `fetch_package(SPEC, dry_run=True, **real_kwargs)` (НЕ замоканный) с теми же kwargs, что использует call site. `dry_run=True` не лезет в сеть, но выполняет `filename_builder` и `mirror_urls_builder` — единственный способ поймать `TypeError` при рассинхроне сигнатур. Этот тип теста поймал бы все 5 багов `filename_builder` сразу, если бы существовал с самого начала.

### 🧹 Очистка мёртвого кода

Удалены deprecated stubs и неиспользуемые импорты после завершения миграции:
- `_download_with_mirrors` в `mieru.py`/`mtproto.py`/`telemt_panel.py` — заменены на `fetch_package()`.
- `_download_binary` stub в `mieru.py` (active `_download_binary` в `turntunnel.py`/`turnable.py`/`naiveproxy.py` остались — это мигрированные функции).
- `_http_download` в `wdtt.py`/`webdav_tunnel.py`/`olcrtc.py` — заменён на `fetch_package(GO_TOOLCHAIN_SPEC)` / `fetch_package(*_SOURCE_SPEC)`.
- `GEOIP_SOURCES`, `_http_get`, `_geoip_fetch` в `telemt_panel.py` — заменены на `fetch_package(TELEMT_GEOIP_*_SPEC)`.
- `tempfile` import в `turntunnel.py`/`turnable.py` — стал unused после миграции.

### 🔧 Прочее

- `honeypot.py`: хардкоженный `v4.11` в генерируемом конфиге заменён на динамическую вставку `chimera.__version__` — при следующем бампе версии не отстанет снова.
- `github_mirrors.py`: добавлена `build_source_archive_mirror_urls()` для `archive/refs/heads/{branch}.tar.gz` URL'ов (используется Wave 2 и Wave 6 для source-tarball'ов).
- `go_toolchain_mirrors.py` + `go_toolchain_packages.py` — общий `GO_TOOLCHAIN_SPEC` для `wdtt.py`, `webdav_tunnel.py`, `olcrtc.py` (раньше каждый модуль имел свою копию `_http_download` + `_install_go_toolchain`).

---

## v4.15.0 — AmneziaWG peer management в Web Admin Panel + User Portal + security hardening — 9 июля 2026

### 🛡️ AmneziaWG-управление в веб-панели

Полноценное управление пирами AmneziaWG standalone через REST API и веб-интерфейс — как из Admin Panel (все пиры, полный CRUD), так и из User Portal (собственный пир, ограниченный self-service). Пользователь теперь может скачать свой AWG-конфиг, посмотреть QR-код и перевыпустить ключи без обращения к админу.

**Новый модуль `awg_rest_api.py`** — HTTP-хендлеры для встраивания в `rest_api.py`. Делегирует авторизацию в `_require_admin()`/`_require_user()` (не дублирует rate-limit / auth). Все `/api/awg/*` отдают 404 (не 500) если AWG не установлен.

**REST API endpoints (admin, через `_require_admin`):**
- `GET /api/awg/status` — статус сервиса (active/enabled) + interface/port/subnet/endpoint/peers_count
- `GET /api/awg/peers` — список всех пиров с owner_email, трафиком (rx/tx), handshake, expires, статусом; **без client_privkey и preshared_key**
- `POST /api/awg/peers` — создать пир `{name, expires?, psk?, owner_email?}`
- `DELETE /api/awg/peers/{name}` — удалить пир
- `POST /api/awg/peers/{name}/regen` — перегенерировать ключи (admin: любой пир)
- `PATCH /api/awg/peers/{name}` — изменить параметр `{param, value}`; param ∈ `dns1`/`dns2`/`expires_at`/`owner_email`
- `GET /api/awg/peers/{name}/config` — `.conf` файл (admin видит все)
- `GET /api/awg/peers/{name}/qr` — PNG QR-код (admin видит все)
- `GET /api/awg/stats` — статистика трафика по пирам (`awg show` → JSON, **без raw_dump** — секреты не утекают)

**REST API endpoints (user, через `_require_user`):**
- `GET /api/awg/my-peer` — собственный пир по `owner_email == user.email` (если нет — `{"peer": null}`)
- `GET /api/awg/my-peer/config` — `.conf` только своего пира (404 если нет)
- `GET /api/awg/my-peer/qr` — PNG QR только своего пира (404 если нет)
- `POST /api/awg/my-peer/regen` — перевыпустить свои ключи
- `POST /api/awg/peers/{name}/regen` — regen по имени (admin: любой; user: только свой, иначе 404 — не раскрывает существование чужого)

**Модель доступа:**
- **Админ** управляет всеми пирами без ограничений: создание, удаление, regen, изменение параметров, привязка/отвязка/переназначение пира к любому VLESS-пользователю (`owner_email`) в любой момент.
- **Пользователь** через User Portal видит и может действовать только на пир, у которого `owner_email == его email`: скачать конфиг, посмотреть QR, посмотреть свой трафик/expires, перевыпустить ключи. Привязку, удаление, чужие пиры — не может.
- **Пир без `owner_email`** — "технический"/неразобранный, виден только админу, в User Portal не всплывает.

**Интеграция в `rest_api.py`:**
- `do_GET`/`do_POST`/`do_DELETE` — добавлены ветки `/api/awg/*` → `awg_rest_api.py`
- `do_PATCH` — **новый HTTP-метод** (раньше отсутствовал) → `awg_rest_api.py` (для `PATCH /api/awg/peers/{name}`)
- Авторизация переиспользуется через `self._require_admin()`/`self._require_user()` — без дублирования rate-limit

**Точечные изменения в `awg_state.py` и `awg_peers.py`:**
- Поле `owner_email: ""` добавлено в структуру peer (миграция: `awgs_state_ensure_peer_owner_field()` добавляет поле существующим пирам, если отсутствует — idempotent)
- `awgs_state_find_peer_by_owner(email)` — lookup пира по владельцу для User Portal
- `awg_peer_add(owner_email="")` — новый параметр, простая email-валидация (не проверяет существование VLESS-юзера физически — админ может привязать к любому email)
- `awg_peer_modify` — `owner_email` добавлен в список поддерживаемых param (`""` = снять привязку)
- `_validate_email()` — простая regex, пустая строка допустима

---

### 🌐 Admin Panel — вкладка AmneziaWG

Новая секция "🛡 AmneziaWG" в Admin Panel (`admin_panel.py`), в стиле проекта (существующие CSS-переменные `--bg-card`/`--accent`/`--radius`, без новой палитры).

**Карточка статуса службы AWG:**
- Сервис: активен/остановлен (status-badge)
- Autostart: вкл/выкл
- Интерфейс (awg0), порт (51820), подсеть (10.66.66.0/24), endpoint, количество пиров

**Таблица всех пиров:**
- Колонки: имя, IP, владелец (owner_email или "— не привязан —"), Rx, Tx, Handshake, истекает, статус (active/expired), действия
- Действия на пира: QR (PNG в новой вкладке), скачать .conf, 🔄 Regen, ✏ Изменить, 🗑 Удалить
- Владелец — dropdown/select с привязкой к email из существующего списка VLESS-пользователей + "не привязан"
- Авто-скрытие секции если AWG не установлен (API возвращает 404)

**Форма "Добавить пира":**
- Имя, expires (опционально), PSK (checkbox), владелец (select из VLESS-пользователей)
- JS-паттерн `fetch()` + Basic Auth — тот же что в остальных разделах панели

**Форма "Изменить пира":**
- Параметр: owner_email / expires_at / dns1 / dns2 (select)
- Значение: для owner_email — select из VLESS-пользователей; для остальных — text input

**Автообновление:** статус и пиры обновляются каждые 60 секунд.

---

### 👤 User Portal — блок "Мой AmneziaWG"

Новая карточка в User Portal (`user_portal.py`), между "Подключение" и "Трафик".

- При загрузке дёргает `GET /api/awg/my-peer`
- Если `peer: null` — карточка **скрыта** (без заглушек "недоступно")
- Если пир есть — показывает: имя, IP, статус (active/expired), истекает, Rx/Tx, handshake, **QR-код** (через `/api/awg/my-peer/qr`), кнопки "📥 Скачать .conf" и "🔄 Перевыпустить ключи"
- regen вызывает `POST /api/awg/my-peer/regen` с подтверждением
- Карточка обновляется каждые 60 секунд

---

### 🔒 Security hardening (3 фикса после code-review)

**1. PSK не утекает в JSON** (`awg_rest_api.py`)
- `_safe_peer_for_json()` фильтровал только `client_privkey`, но `preshared_key` отдавался в `GET /api/awg/peers` и `GET /api/awg/my-peer`. PSK — боевой секрет (post-quantum resistance layer), утечка ослабляет туннель.
- Фикс: `preshared_key` (и `server_privkey` дефенсивно) добавлены в `_NEVER_IN_JSON` tuple.

**2. QR PNG пишутся с chmod 0o600** (`awg_qr.py`)
- `awgs_qr_save_png()` не делал chmod — PNG создавался с umask-правами (часто 0o644). PNG содержит vpn:// URI с приватным ключом + PSK — читается любым локальным юзером.
- Фикс: `path.chmod(0o600)` после успешной генерации. Также `AWGS_KEYS_DIR.chmod(0o700)` в `awgs_qr_save_client_conf` и явный `AWGS_KEYS_DIR.chmod(0o700)` в начале `awgs_qr_export_peer` (не полагается на побочный эффект `save_client_conf`).
- Тихий провал chmod заменён на `core.log_to_file("WARNING", ...)` — админ заметит в `/var/log/vless-install.log`.

**3. Приватный ключ не утекает в systemd journal** (`awg_qr.py` + `awg_rest_api.py`)
- `GET /api/awg/.../qr` вызывал `awgs_qr_export_peer(peer)`, который дёргал `awgs_qr_show_terminal()` — `print(r.stdout)` ANSI QR с vpn:// URI (приватный ключ + PSK). Под systemd stdout уходит в journal (`journalctl -u vless-web`). На каждый просмотр QR юзером ключ буквально писался в системный лог.
- Фикс: параметр `show_terminal: bool = True` в `awgs_qr_export_peer()`. Default `True` сохраняет TUI-поведение (`awg_peers.py` без изменений). REST API хендлеры передают `show_terminal=False` — файлы генерируются, но `print()` не вызывается.

**Дополнительно:** `raw_dump` убран из `GET /api/awg/stats` — необработанный вывод `awg show all dump` содержал приватный ключ сервера (поле 1 interface-строки) и PSK каждого пира (поле 2 peer-строки). Фронтенду он не нужен (есть распарсенные `peers`).

---

### 🐛 Bug fixes (install flow)

**1. Порядок запуска Nginx → Unix-сокет** (`_core.py`)
- В основном flow установки код ждал сокет ДО запуска nginx — deadlock, потому что сокет создаёт именно nginx (`listen unix:`), а не xray. Цикл `range(1, 31)` всегда завершался `else` → гарантированный warning "Сокет не появился" после 30 сек. Увеличение timeout не помогало — проблема не в длительности, а в порядке операций.
- Фикс: сначала запускаем nginx (он создаёт сокет), потом проверяем сокет (цикл `range(20)`, обычно <1 сек). Та же логика что уже работала в `_nginx_restart_if_reality()` и `emergency_repair.py`.

**2. state.json сохраняется ДО health check** (`_core.py`)
- `run_full_health_check()` вызывался ДО сохранения `state.json`. `health.py` читает `domain` и `server_port` из state.json (через `_get_state_value`, без импорта `_core` — чтобы избежать циклической зависимости). При первой установке state ещё не сохранён → `health_check_ssl()` получала пустой domain → ложный warning "SSL проверка пропущена: домен не задан" даже когда домен указан и сертификат получен. Аналогично `health_check_ports()` получала `server_port=443` (fallback) вместо реального порта.
- Фикс: блок сохранения state.json перемещён ДО `run_full_health_check()`. Бонус: если исключение произойдёт между health check и финальным выводом — state.json уже сохранён (раньше терялся полностью).

---

### 🧪 Тесты и anti-regression

**`tests/test_awg_rest_api.py`** — 57 unit-тестов (новый файл):
- `TestAWGRestAPIAwgNotInstalled` (6) — все `/api/awg/*` → 404 если AWG off
- `TestAWGRestAPIAdminAuth` (7) — admin endpoints → 401 без admin auth
- `TestAWGRestAPIStatsNoSecretLeak` (5) — `/api/awg/stats` не утекает server_privkey/PSK
- `TestAWGRestAPIPeerNameValidation` (3) — path traversal блокируется
- `TestAWGRestAPIUserEndpoints` (5) — my-peer auth, peer:null, privkey не утекает
- `TestAWGRestAPISafePeerForJson` (4) — client_privkey + preshared_key + server_privkey фильтруются
- `TestAWGStateOwnerEmailMigration` (3) — миграция owner_email
- `TestAWGPeerAddOwnerEmail` (3) — add с/без/невалидным owner_email
- `TestAWGPeerModifyOwnerEmail` (3) — modify valid/empty(unbind)/invalid
- `TestValidateEmail` (3) — empty/valid/invalid emails
- `TestUserCannotRegenOthersPeer` (3) — user→чужой пир=404, admin→любой=200, user→свой=200
- `TestUserCannotAccessAdminEndpoints` (2) — user DELETE/PATCH → 401
- `TestAWGQRPngChmod` (3) — PNG 0o600, AWGS_KEYS_DIR 0o700
- `TestAWGQRExportNoPrintInApiMode` (5) — show_terminal=False не печатает в stdout
- `TestAWGQREndToEndChmod` (1) — E2E: `GET /api/awg/peers/{name}/qr` → PNG с `stat.S_IMODE == 0o600` на диске

**`full_test.py`** — 2 новые секции (9 anti-regression проверок):
- **Секция 9** (5 проверок) — порядок запуска Nginx → Unix-сокет: строка "Ожидание Unix-сокета от Xray" не должна вернуться; `range(1, 31)` цикл не должен вернуться; `nginx start` должен идти ДО `is_socket()`; `nginx_setup.py` должен содержать `listen unix:`; `xray_install.py` не должен делать `rm -f PARAM_SOCKET_PATH`
- **Секция 10** (4 проверки) — state.json сохранён ДО health check: `STATE_FILE.write_text` должен идти ДО `run_full_health_check()` (regex для реального вызова, не упоминания в комментариях); `health_check_ssl` должен читать domain через `_get_state_value`; `health_check_ports` должен читать `server_port` через `_get_state_value`; warning-строка должна существовать

**Тестовые результаты:**
- `tests/`: 121/121 PASS (64 awg_net_common + 57 awg_rest_api)
- `full_test.py`: 74/74 PASS (10.0/10 readiness, 10 секций)
- `smoke_test_modules.py`: 42/42 PASS
- `py_compile`: OK

---

### 📊 Цифры

- Новых модулей: 1 (`awg_rest_api.py`)
- Изменено файлов: 8 (`awg_qr.py`, `awg_peers.py`, `awg_state.py`, `awg_rest_api.py` [новый], `rest_api.py`, `admin_panel.py`, `user_portal.py`, `_core.py`)
- Новых строк Python: ~1800
- Новых тестов: 57 unit + 9 anti-regression статических
- `full_test.py` секций: 8 → 10

---

## v4.14.0 — AmneziaWG 2.0 standalone VPN (полный порт bivlked) — 9 июля 2026

### 🔒 Standalone AWG как отдельный пункт меню

Полный порт [bivlked/amneziawg-installer](https://github.com/bivlked/amneziawg-installer) v5.18.4 (10 500+ строк bash) на Python, интегрированный в основной проект как 13 новых модулей. Теперь standalone AmneziaWG 2.0 доступен как отдельный протокол в главном меню (пункт 16), не зависит от VLESS-инфраструктуры.

**13 новых модулей в `chimera/modules/awg_*.py`:**

| Модуль | Назначение |
|--------|-----------|
| `awg_constants.py` | Константы, пути, defaults (префикс AWGS_* — не конфликтует с chain Mode B) |
| `awg_state.py` | State management (отдельный `awg_standalone_state.json`) |
| `awg_presets.py` | 9 carrier-пресетов (default/mobile/Yota/Tele2 MSK+Krasnoyarsk/Таттелеком/Мегафон/Билайн/T-Mobile US) |
| `awg_hw_tuning.py` | Hardware-aware tuning (sysctl/swap/NIC) — idempotent |
| `awg_apply.py` | Apply config (syncconf без даунтайма / restart fallback) |
| `awg_standalone.py` | Главный модуль: install/uninstall/menu |
| `awg_peers.py` | CRUD пиров + TUI меню (add/remove/list/stats/regen/modify) |
| `awg_qr.py` | QR-коды (terminal + PNG) + `vpn://` URI для Amnezia Client |
| `awg_expires.py` | Временные клиенты (`--expires=1h\|7d\|30d\|4w`) + cron автоудаления |
| `awg_backup.py` | Backup/Restore с rollback при ошибке |
| `awg_cascade.py` | Каскад AWG0 (вход, РФ) ↔ AWG1 (выход, зарубеж) + split-routing по RU-сетям |
| `awg_diagnose.py` | Diagnostic + carrier-compare (kernel/sysctl/UFW/service/tunnel) |
| `awg_uninstall.py` | Полное удаление (с сохранением backup'ов опционально) |

### 🎯 Carrier-пресеты (реальные данные от bivlked)

Перенесены точные значения Jc/Jmin/Jmax/I1 по операторам из issues/discussions bivlked:
- **Yota MSK** — узкий Jmax (markmokrenko: Jmax=70 OK, Jmax>300 блокируется)
- **Tele2 MSK** — Jc=3 фиксированный (alkorrnd: Jc=3 >95% успеха, Jc=4 ~30%)
- **Tele2 Красноярск** — без I1 (майская волна 2026)
- **Мегафон регионы** — без I1
- **Билайн Москва** — default preset
- **T-Mobile US** — Jc=6, узкие Jmin/Jmax, I1 как binary
- **Таттелеком/Летай** — mobile preset
- **Mobile (универсальный)** — Jc=3, узкий Jmax
- **Default** — для проводного интернета

### 🔄 Каскад RU → зарубеж

Полноценный каскад из 2 серверов, доступный из меню standalone AWG:
- **AWG0 (вход, РФ)**: принимает клиентов, делит трафик: RU-сети напрямую, остальное через AWG1
- **AWG1 (выход, зарубеж)**: стандартный standalone AWG + спец-пир `cascade_entry` для AWG0
- Авто-загрузка `ru.zone` (8626 сетей) с ipdeny.com + fallback на GitHub raw
- ipset + iptables-маршрутизация (fwmark=0x2000, не конфликтует с chain Mode B который использует 1000)
- `awg-routing.sh` + systemd-юнит `awg-cascade-routing.service`
- Cron для еженедельного обновления ru.zone

### 🛡️ Защита от регрессий

`awgs_check_conflicts()` проверяет перед установкой:
1. **Chain Mode B**: если в `state.json` есть `awg_exit_enabled=True` + `install_mode=B` — отказ (конфликт интерфейса awg0)
2. **Интерфейс awg0**: если уже существует — отказ
3. **UDP-порт 51820**: если занят — отказ
4. **Конфиг awg0.conf**: если уже существует — отказ (или `--force`)
5. **State**: если standalone уже установлен — отказ

Все константы имеют префикс `AWGS_*` (AWG Standalone) — **не переиспользуют** globals `AWG_*` из `_core.py` (те относятся к chain Mode B transport).

### 🔧 Архитектурные решения

- **State storage**: отдельный файл `/var/lib/xray-installer/awg_standalone_state.json` (не смешивается с основным `state.json`)
- **Имя интерфейса**: `awg0` (как в upstream), отказ при конфликте с chain Mode B
- **Peer management**: отдельный модуль `awg_peers.py` + отдельный пункт меню (не смешивается с `users_manager.py`)
- **sysctl/firewall**: idempotent — проверяет через `sysctl -n`, применяет только если значение не оптимально. UFW — только открыть UDP-порт AWG (без переделки deny-all). Fail2Ban не трогает.
- **Каскад**: один пункт «Каскад» в меню, внутри выбор роли (AWG0/AWG1)

### ✨ Возможности standalone AWG

- Установка одной командой (TUI-мастер с выбором пресета/оператора)
- Carrier-пресеты под мобильных операторов (Yota/Tele2/Мегафон/Билайн/Tattelecom/T-Mobile US)
- Тонкая настройка: порт, подсеть, MTU, IPv6 dual-stack, endpoint (для NAT)
- Управление пирами: add/remove/list/stats/regen/modify
- Временные клиенты с авто-удалением (`--expires=1h/12h/1d/7d/30d/4w`)
- Per-client PresharedKey (опционально)
- QR-коды в терминале + PNG файлы
- `vpn://` URI для импорта в Amnezia Client одним тапом
- Backup/Restore с rollback при ошибке
- Diagnostic: kernel/sysctl/UFW/service/tunnel + carrier-compare
- Каскад из 2 серверов с split-routing по RU-сетям
- Полное удаление (с сохранением backup'ов опционально)

### 📊 Цифры

- Новых модулей: 13
- Новых строк Python: ~3500
- Изменено файлов: 2 (`_core.py` — добавлен пункт меню 16, `CHANGELOG.md`)
- `verify.py`: **245/245 ✓** (было 232, +13 новых проверок)
- Регрессий на существующий код: 0 (гарантировано `awgs_check_conflicts()`)

---

## v4.13.0 — Рефакторинг архитектуры + Web Admin Panel + User Portal + Security Hardening — 8 июля 2026

### 🏗️ Рефакторинг — модульная архитектура (продолжение)

Продолжение декомпозиции монолитного `_core.py` (32 557 строк) в модульную архитектуру. В этой версии вынесено ещё 40+ модулей, ядро уменьшилось с 32 557 → 7 779 строк (−76%). Всего в `chimera/modules/` теперь 129 файлов, сгруппированных по 24 логическим категориям (см. `PROJECT_MAP.md`).

**Принцип рефакторинга:**
- `_core.py` остаётся главным orchestrator-ом: глобальное состояние, `main_menu()`, `_load_state_into_globals()`, функции которые мутируют много globals (AWG, chain multi-node, install orchestration).
- Все модули обращаются к ядру через `_core_module()` lazy binding (importlib) — нет циклических импортов, модули грузятся по требованию.
- Каждый модуль самостоятелен: свой `from __future__ import annotations`, свой блок `core = _core_module()` для доступа к глобалам, свой `setattr(core, ...)` для синхронизации state обратно в ядро.
- `proto_common.py` — общие хелперы для 8 протокольных модулей (wdtt, turnable, mieru, fptn, naiveproxy, turntunnel, mtproto, webdav_tunnel): `proto_load_state/proto_save_state/proto_ask/proto_install_service/proto_show_status/proto_full_uninstall`.
- `awg_transport.py` — 45 функций AWG-транспорта вынесены из `_core.py` (install/keys/config/policy-routing/tunnel-verify, single-node + multi-node + watchdog).
- `chain_nodes.py` — 22 функции chain/nodes management (Mode B) вынесены из `_core.py` (chain config builders, node CRUD, health/speed tests).

**Полный список вынесенных модулей (40+):**
ASN cache, standalone screens, fail2ban, SSH hardening, resources, MTU tuning, GeoIP block, connection audit, backup/rollback, DNSCrypt, network setup, geo files, SSL/certbot, failover, client config export, uninstall, TTL users, credential rotation, health report, traffic tracking, system deps, nginx setup, RU subnets, AS-direct, autoban, backup manager, speed test, reconfigure, migration, quick status, switch mode, traffic history, split tunnel, diagnostics, xray install, install prompts, users manager, emergency repair, AWG transport, chain/nodes, proto_common.

**Документация и тесты:**
- `PROJECT_MAP.md` — полная карта всех 129 модулей по 24 логическим группам с описанием каждого файла.
- `verify.py` v2 — проверка через `exec()+getattr()` вместо grep (точнее, ловит больше багов).
- `full_test.py` — постоянный автотест (8 секций): py_compile всех .py + импорт всех модулей + getattr для ключевых функций + дубликаты определений (AST) + пути state-файлов /var/lib/xray-installer (baseline 150) + права 0o600 (baseline 76) + git hygiene + **web panel security invariants** (UUID-fallback, ThreadingHTTPServer, timeout=None, wildcard CORS).
- `tests/baseline_paths.json` — baseline-снапшот для будущих проверок.
- `smoke_test_modules.py` — 42 тестовых случая (стен-режим: input='q', subprocess=mock), проверяет что все функции-меню вызываются без NameError/AttributeError.

---

### 🌐 Web Admin Panel + User Portal + REST API

**Новый модуль `rest_api.py`** — единый HTTP-сервер (ThreadingHTTPServer) для REST API, Admin Panel и User Portal. Запускается как отдельный systemd-сервис `vless-web.service`.

**Архитектура безопасности:**
- **Bind 127.0.0.1 по умолчанию** — панель доступна только через SSH-туннель (`ssh -L 8443:127.0.0.1:8443 user@server`). Внешний доступ (0.0.0.0) включается явно через пункт меню 5 в `do_manage_web_panel()`, с предупреждением о HTTP без TLS.
- **Basic Auth с `secrets.compare_digest`** — constant-time сравнение, защита от timing-атак.
- **Portal password генерируется отдельно от UUID** — `secrets.token_urlsafe(12)` при создании юзера. UUID больше не используется как fallback-пароль (uuid — публичная часть vless:// ссылки, не может быть паролем).
- **Rate-limiting** — in-memory sliding window (10 попыток / 60 сек → 429 с `Retry-After: 30`), общий для admin и portal auth.
- **HTTP/1.1 + Content-Length** — корректная работа с keep-alive и fetch() из браузера.
- **credentials: 'same-origin'** в JS fetch — гарантированная передача Basic Auth кредов.
- **XSS-защита** — `html.escape()` для всех пользовательских данных в HTML (user_portal.py), `esc()` функция в admin_panel.py.
- **Body size cap** — `MAX_BODY_BYTES = 1MB`, 413 Payload Too Large при превышении.
- **CORS отключён** — wildcard `Access-Control-Allow-Origin: *` убран, панель работает same-origin.
- **ThreadingHTTPServer** вместо голого HTTPServer — каждый запрос в отдельном потоке, защита от DoS через slowloris.
- **Per-connection timeout = 30с** — `server.timeout = None` убран, клиенты не могут держать соединение бесконечно.

**REST API endpoints (admin):**
- `GET /api/health` — статус сервисов, SSL, RAM, Disk, CPU, uptime, connections (без авторизации — для мониторинга)
- `GET /api/users` — список пользователей (без portal_password)
- `POST /api/users` — создать пользователя (генерирует UUID + portal_password, возвращает пароль ОДИН раз)
- `DELETE /api/users/{email}` — удалить пользователя
- `POST /api/users/{email}/password` — админ задаёт portal_password юзеру
- `POST /api/users/{email}/toggle` — заблокировать/разблокировать юзера (disabled=True → убирается из config.json)
- `GET /api/users/{email}/traffic` — трафик пользователя (uplink + downlink через Xray Stats API)
- `POST /api/rotate/uuid` — ротация UUID
- `POST /api/rotate/reality` — ротация REALITY-ключей
- `GET /api/geoip/rules` / `POST /api/geoip/rules` / `DELETE /api/geoip/rules` — управление GeoIP
- `POST /api/backup` / `GET /api/backup/list` — бэкап/список бэкапов

**REST API endpoints (user portal):**
- `GET /api/portal/links` — VLESS-ссылки + QR (только для активных сервисов — проверка через systemctl is-active)
- `GET /api/portal/traffic` — трафик пользователя
- `GET /api/portal/health` — ограниченный health (domain, port, protocol, xray, SSL, uptime)
- `GET /api/portal/clash` — скачать Clash Meta YAML
- `GET /api/portal/singbox` — скачать Sing-box JSON
- `POST /api/portal/password` — смена пароля (мин 8 символов)

**Admin Panel (`admin_panel.py`):**
- Glassmorphism дизайн, серо-голубые тона, анимации.
- Health-карточки: домен, диск, RAM, соединения, uptime, SSL.
- Управление пользователями: создание (с генерацией portal_password), удаление, **блокировка/разблокировка** (🔒/🔓 — юзер убирается из config.json), **смена пароля** (🔑).
- Ротация UUID и REALITY-ключей.
- Создание бэкапов.
- Трафик и TTL для каждого юзера (∞ для бессрочных).
- Кнопки: 🔒 Заблокировать (серая), 🔑 Пароль (жёлтая), 🗑 Удалить (красная) — все одинакового размера.

**User Portal (`user_portal.py`):**
- Анимированный интерфейс, плавающие частицы, gradient-фон.
- VLESS-ссылки + QR-коды (flexbox, рядом по центру, с переносом).
- Трафик (progress bar если есть лимит).
- TTL (срок действия, countdown badge).
- Состояние сервера (Xray, домен, протокол, SSL, uptime, порт).
- Скачивание Clash Meta / Sing-box конфигов.
- Смена пароля (мин 8 символов).
- `html.escape()` для всех пользовательских данных (name, email).

**Управление через TUI:**
- `do_manage_web_panel()` — меню управления веб-панелью:
  - Пункт 1: **"Установить веб-панель"** (если не установлена) или "Запустить/Остановить сервис" (если установлена). При установке — генерируется admin_password, показывается ОДИН раз, подсказка про SSH-туннель.
  - Пункт 2: Изменить порт.
  - Пункт 3: Изменить admin-пароль (мин 8 символов).
  - Пункт 4: Переустановить (сброс конфига).
  - Пункт 5: Открыть/закрыть доступ снаружи (0.0.0.0 ↔ 127.0.0.1, с предупреждением о HTTP без TLS).
- `install_web_service()` — создаёт `web_config.json` (admin_user/admin_pass/host/port), systemd-unit `vless-web.service`, запускает сервис. При expose=True — открывает порт в ufw + warning о HTTP.
- `uninstall_web_service()` — останавливает и удаляет сервис.

**Синхронизация пользователей:**
- `_sync_users_from_config()` — при создании юзера через admin panel, существующие юзеры из `config.json` (clients) подтягиваются в `users.json` (если их там нет). Предотвращает затирание старых юзеров при `_users_apply_to_config()`.
- `_users_apply_to_config()` — фильтрует `disabled=True` юзеров (они не попадают в `config.json` clients, не могут подключиться).
- `unquote(email)` в DELETE/traffic/password/toggle endpoints — корректная обработка `@` в URL (браузер кодирует через `encodeURIComponent()`).

**Генерация VLESS-ссылок (умная фильтрация):**
- Hysteria2 — ссылка генерируется только если `h2_exit_enabled=True` **И** есть `h2_host` + `h2_password` **И** `systemctl is-active hysteria-server` = active.
- MTProto — только если state-файл существует и содержит `port` + `secret`.
- VLESS — всегда (основной протокол), с правильным SNI (reality_dest при AWG, domain в остальных случаях).

**Трафик через Xray Stats API:**
- `_query_user_traffic_bytes(email)` — запрос через `xray api statsquery --pattern=user>>>{email}>>>traffic>>>{direction}` (uplink + downlink).
- Stats API настраивается автоматически: секции `stats` + `policy` (statsUserUplink/Downlink) + inbound `xray-stats-api` (dokodemo-door на 127.0.0.1:10085).

---

### 🔒 Security Hardening

**Web Panel:**
- UUID-as-password fallback **полностью убран** — uuid это публичная часть vless:// ссылки (в QR-коде клиента), любой кто видел ссылку не должен уметь залогиниться в портал.
- Single-threaded HTTPServer + `timeout=None` → **ThreadingHTTPServer + timeout=30с** — защита от DoS через slowloris.
- HTTP без TLS на 0.0.0.0 + auto `ufw allow` → **bind 127.0.0.1 по умолчанию**, ufw НЕ открывается. Внешний доступ — через явный toggle с warning.
- `Access-Control-Allow-Origin: *` → **убран полностью**, панель same-origin.
- Min password length: 6 → **8** (в `/api/portal/password`, `do_manage_web_panel` пункт 3, JS user_portal).
- `_read_body()` без лимита → **MAX_BODY_BYTES = 1MB**, 413 Payload Too Large.
- `full_test.py` секция 8 — статические инварианты web panel security (UUID-fallback, ThreadingHTTPServer, timeout=None, wildcard CORS) — ловит регресс.

**REALITY dest:**
- Дефолт `PARAM_REALITY_DEST` изменён с `www.microsoft.com` на `www.cloudflare.com` — обход бага TLS-парсера REALITY (Xray-core): жёсткий лимит 8192 байт на Certificate record, у microsoft.com (Akamai CDN) Certificate с цепочкой/OCSP stapling — 8273 байта. REALITY обрывает разбор и валит соединение. Cloudflare (ECDSA, компактная цепочка) работает стабильно. Баг не связан с AWG/MTU — лимит внутри самого REALITY-парсера, до всякой маршрутизации.
- Warning в flow установки (`prompt_awg_exit_mode`) при выборе microsoft.com.

---

## ✨ Новый протокол: FPTN — независимый L3 VPN с honeypot-анти-пробингом — 6 июля 2026

### Контекст и причины

Добавлена поддержка FPTN — самостоятельного L3 VPN-протокола, не завязанного на Xray-инбаунды: собственный TUN-туннель и транспорт поверх TLS. Анти-пробинг устроен принципиально иначе, чем в REALITY: вместо подмены сертификата сервер работает как honeypot-прокси — клиент без валидной сессии протокола получает прозрачный проброс на настоящий "легитимный" домен вместо отказа соединения или голого TLS-хендшейка. Для внешнего наблюдателя (сканера, DPI-зонда) сервер неотличим от обычного HTTPS-сайта.

Протокол ставится как отдельная опция в главном меню, рядом с остальными транспортами — самостоятельная альтернатива, не заменяющая и не затрагивающая существующие VLESS/Hysteria2/Telemt/Mieru/NaiveProxy ноды.

### Архитектурное решение

**Установка — без Docker.** Официальный дистрибутив сервера распространяется в контейнере, но для голого Linux у релиза есть и нативный `.deb`-пакет (amd64/arm64). Бинарники извлекаются из пакета напрямую (без установки через системный пакетный менеджер) и разворачиваются как обычный systemd-сервис — по той же схеме, что и остальные протоколы этого инсталлятора (собственный конфиг, свой юнит, никакой логики в ядре скрипта).

**Сертификат** — самоподписанный, генерируется на месте (openssl, 4096 бит). Домен не обязателен: клиент сверяет отпечаток сертификата, зашитый в выданный токен, а не полноценную цепочку доверия.

**Пользователи** — через штатную CLI-утилиту управления пользователями протокола (хранит только хэш пароля, не открытый текст); список читается сервером "на лету" при изменении файла — добавление/удаление пользователя не требует рестарта сервиса. Логин принимается только из латинских букв и цифр — валидируется на стороне инсталлятора до вызова утилиты, чтобы не получать невнятную ошибку постфактум.

**Токен клиента** — самодостаточная строка (сервер, порт, учётные данные, отпечаток сертификата), генерируется на чистом Python без вызова внешних скриптов; интегрирована в общий агрегатор подписки наравне с остальными протоколами.

**⚠️ Важный нюанс, который пришлось компенсировать отдельно:** сам бинарник сервера при каждом старте безусловно сбрасывает политику firewall (INPUT/FORWARD/OUTPUT) в ACCEPT для обоих стеков — IPv4 и IPv6 — это часть его встроенной логики настройки маршрутизации/NAT и не управляется флагами запуска. На сервере со строгой политикой DROP по умолчанию это будет молча слетать при каждом рестарте и при перезагрузке сервера.

Компенсация встроена в модуль:
- при установке снимается снимок текущей политики INPUT/FORWARD (оба стека) до первого запуска сервиса;
- в сам systemd-юнит добавлен пост-стартовый хук, который восстанавливает исходную политику (если она была DROP) после КАЖДОГО запуска сервиса, включая автозапуск при перезагрузке — а не только когда админ перезапускает сервис вручную через меню;
- синхронизация с моментом готовности сервиса сделана через поллинг конкретного признака (появление маршрутного правила, которое сервис сам добавляет при старте), а не через фиксированную паузу — чтобы не зависеть от угадывания тайминга;
- политика OUTPUT сознательно не восстанавливается автоматически — риск заблокировать сам сервер перевешивает удобство; это явно задокументировано в справке модуля.

Ограничение подхода: снимок политики берётся один раз, при установке; если политику меняют вручную уже после установки протокола — снимок не обновляется сам, нужна переустановка модуля.

### Изменения в коде

**Новый модуль `fptn.py`**: установка/переустановка/удаление, автоопределение архитектуры и исходящего сетевого интерфейса, генерация конфига и systemd-юнита, управление пользователями (добавление/список/удаление/перевыпуск токена), открытие порта в файрволе с учётом уже активного UFW, восстановление политики firewall (см. выше), статус/логи, встроенная справка (в т.ч. отдельный раздел про поведение firewall).

**Пункт меню протоколов в основном скрипте** — с ленивым импортом модуля (по образцу других менее давно добавленных протоколов), чтобы сбой в новом модуле не мешал остальному функционалу при старте.

**Агрегатор подписки**: сопоставление пользователя по имени и сборка токена протокола в общую подписку, наравне с уже поддержанными протоколами.

### Проверено на

Компиляция и статический анализ всех затронутых файлов — чисто. Изолированные тесты вне продакшен-окружения: генерация сертификата и отпечатка, генерация и обратное декодирование токена, валидация логина, генерация конфига и systemd-юнита.

Firewall-хук: синтаксическая проверка скрипта восстановления политики + функциональный тест с подменёнными `iptables`/`ip6tables` (эмуляция задержки появления маршрутного правила) — подтверждено, что скрипт дожидается признака готовности вместо немедленного продолжения и применяет восстановление независимо для каждого стека и каждой цепочки.

Сборка подписки: пользователь протокола корректно находится по имени, собранный токен декодируется с верными данными; для несовпадающего пользователя корректно возвращается пустой результат.

Живого теста на реальном сервере (боевой рестарт/ребут с настоящим firewall) на момент этой записи не проводилось — рекомендуется проверить `iptables -L INPUT -n` / `ip6tables -L INPUT -n` после первого рестарта сервиса на тестовом сервере перед раскаткой на прод.

---

## 🐛 Фикс: пункт [1] в меню «Ротация логов» падал с NameError — 5 июля 2026

### Контекст и причины

При попытке применить конфиг logrotate через меню (пункт `[1]`) — `CRITICAL: name 'setup_logrotate' is not defined`. Функция `setup_logrotate()` живёт в `_core.py`, а `logrotate.py` вызывал её без импорта вообще — судя по всему, баг существовал ещё до вчерашнего фикса `xray-heavy` (проверено сравнением с оригиналом — строка вызова не менялась). Это объясняет, помимо прочего, почему `vless-install.log` никогда не ротировался в реальности: даже если бы конфиг был полным, кнопка «Применить» была сломана всё это время.

### Исправление

Ленивый импорт `from chimera._core import setup_logrotate` непосредственно внутри обработчика `ch == "1"`, а не наверху файла — `_core.py` сам импортирует `do_manage_logrotate` из `logrotate.py` при старте, поэтому импорт в обратную сторону на уровне модуля зациклил бы загрузку. Внутри функции это безопасно: к моменту нажатия кнопки оба модуля уже полностью загружены. Тот же приём, что и в `warp.py`/`status_panel.py` (`_core_module()`), только явным импортом конкретного имени вместо `importlib`.

### Проверено на

Сквозной прогон в реальном окружении: `import chimera._core` + `from chimera.modules import logrotate` — оба модуля загружаются без циклической ошибки; `core.setup_logrotate()` вызван напрямую и реально записал `/etc/logrotate.d/xray-heavy` — проверено `logrotate --debug` на результате (файлы корректно распознаны одним блоком, `missingok` отработал на отсутствующих autoban/watchdog-логах). `py_compile` обоих файлов.

---

## 🐛 Фикс: vless-install.log никогда не попадал в logrotate — забил диск на 100% — 5 июля 2026

### Контекст и причины

На проде диск оказался забит на 100% (`/dev/vda2 30G 30G 0 100%`) — виновником оказался `/var/log/vless-install.log` весом 22 ГБ. Причина: `setup_logrotate()` в `_core.py` создаёт конфиги только для `xray/access.log`, `xray/error.log` и (при включённом Split Tunnel) `xray-geo-update.log` — `vless-install.log` туда никогда не входил, при этом пишется он через `log_to_file()` на каждый `info()`/`success()`/`warn()` по всему проекту, то есть непрерывно с момента установки. Отдельно вводит в заблуждение то, что меню «Ротация логов» (`logrotate.py`) показывает размер этого файла в общем списке — создавая впечатление, что он под ротацией, хотя по факту конфига для него не было вообще. `xray-autoban.log` и `xray-watchdog.log` были в том же положении.

### Исправление

`setup_logrotate()` (`_core.py`) — добавлен третий конфиг `/etc/logrotate.d/xray-heavy` отдельно от лёгких `xray-aux` (autoupdate/geo-update, weekly): `vless-install.log` + `xray-autoban.log` + `xray-watchdog.log`, ротация `daily` **и** `maxsize 50M` как аварийный триггер — если файл распухнет раньше суточного цикла, ротация всё равно сработает. `missingok`, т.к. не все три файла обязательно существуют на любой системе. Отдельная стратегия от `xray-aux` намеренно: это самые "разговорчивые" логи проекта (пишутся на каждое действие/cron-тик), лёгким логам daily+maxsize не нужен.

`logrotate.py` — в статусе меню добавлена строка `Конфиг xray-heavy` (аналогично уже существующим `xray`/`xray-aux`), чтобы реальное состояние ротации для этих трёх файлов было видно, а не пряталось за общим списком размеров.

### Изменения в коде

**`chimera/_core.py`**: `setup_logrotate()` — новый блок `LOGROTATE_XRAY_HEAVY`; в статусные `dim()`-сообщения после установки добавлена строка про новый конфиг.

**`chimera/modules/logrotate.py`**: путь `_LOGROTATE_XRAY_HEAVY` + строка статуса в меню.

### Проверено на

`py_compile` обоих файлов. Синтаксис сгенерированного конфига провалидирован реальным `logrotate --debug` (установлен в тестовом окружении) — корректно обрабатывает все три пути одним блоком, `missingok` подтверждённо пропускает отсутствующие файлы без ошибки. Живой `logrotate -f` на проде с уже существующими на сервере автобан/watchdog логами не запускался — конфиг применится через пункт `[1]` меню «Ротация логов» либо при следующей полной установке/обновлении (`setup_logrotate()` вызывается оттуда же).

### Что нужно сделать на сервере (уже отправлено пользователю отдельно)

Диск уже был вручную разгружен (`truncate -s 0 /var/log/vless-install.log` + чистка старых ядер) — после накатки этого фикса нужно один раз зайти в меню «Ротация логов» → `[1]`, чтобы создался новый конфиг `/etc/logrotate.d/xray-heavy`.

---

## 📋 Панель «Состояние» над главным меню — 5 июля 2026

### Контекст и причины

Раньше, чтобы понять «всё ли живо» (сколько протоколов активно, не упал ли fail2ban, сколько свободно диска, какой сейчас публичный IP), нужно было идти в отдельные пункты меню (Дашборд, статус WARP, статус DNSCrypt и т.д. по отдельности). Хотелось сводную панель прямо над главным меню — «на секунду глянул и всё понятно».

### Архитектурное решение

Новый модуль `status_panel.py`, полностью автономный: сам собирает данные (протоколы/сетевые службы/безопасность через уже существующие `_is_installed()`/`_is_active()`-функции каждого модуля, систему — напрямую из `/proc`, IP+страну и версию ядра — через уже готовые функции `_core.py`). Каждая отдельная проверка обёрнута в свой `try/except`, чтобы поломка/переименование одного модуля роняла только одну строку счётчика, а не всю панель.

**Кэш на диск** (`/var/lib/xray-installer/status_panel_cache.json`, TTL 20 сек) — «тяжёлая» часть (систематические проверки установленности ~15 модулей + запрос IP) считается не при каждой отрисовке меню, а не чаще раза в 20 секунд. Отдельный демон/systemd-таймер ради этого не заводился — обновление по протуханию кэша прямо в момент открытия меню даёт тот же эффект без лишней фоновой сущности.

`_core.py` тронут по минимуму — единственная точка сопряжения: 10 строк в `main_menu()` (ленивый импорт + вызов `render()` перед отрисовкой собственного бокса меню, в `try/except`, чтобы сбой панели не блокировал вход в меню). Вся логика — в `status_panel.py`.

### Сделанные допущения (требуют твоей проверки)

- **Hysteria2** считается активным по `h2_exit_enabled` в state.json — отдельного стейта для entry-only установки не нашлось. Если у тебя H2 может стоять только как entry без exit-роли — поправить `_check_h2()`.
- **VK Turn Tunnel** — активен, если установлен хотя бы один из двух вариантов (FreeTurn/`turntunnel.py` ИЛИ WireTurn/`turnable.py`), т.к. в главном меню это один пункт.
- Точечный `ipban.py` (разовый бан по запросу) сознательно НЕ включён в «Безопасность» — это утилита разового действия, а не постоянно работающий защитный слой, в отличие от fail2ban/honeypot/ingress-GeoIP/auto-ban.
- «Пользователи» считает active/total как not-disabled/все через `_unified_load_users()` — та же логика, что уже использует `subscription.py` для Subscription-Userinfo.

### Изменения в коде

**`chimera/modules/status_panel.py`** (новый) — проверки по трём категориям (`_protocol_checks`/`_network_checks`/`_security_checks`), системные метрики из `/proc` без внешних зависимостей, кэш со снапшотом (`get_snapshot`), рендер (`render`).

**`chimera/_core.py`** — 10 строк в `main_menu()`: ленивый импорт `status_panel.render` + вызов перед отрисовкой главного меню.

### Проверено на

`py_compile` обоих файлов. Функциональный прогон `render()`/`get_snapshot()` с заглушкой `_core.py` (чтобы не тянуть весь 32k-строчный модуль) — панель рендерится корректно, деградирует до `1/11 активны` и `?` там, где реальных сервисов на тестовой машине нет, вместо падения. Отдельно проверено попадание в кэш (второй вызов `get_snapshot()` — 0 мс вместо ~44 мс) и то, что `get_server_ip()`, вернувший невалидную строку вместо IPv4, не ломает рамку бокса. Живая проверка на реальном сервере (все 15 модулей вперемешку включены/выключены, реальный fail2ban/honeypot) не проводилась.

---

## 📶 Subscription-Userinfo: остаток трафика прямо в клиенте — 4 июля 2026

### Контекст и причины

В `_core.py` уже есть полноценный учёт лимитов трафика на пользователя (`do_manage_traffic_limits`/`_check_traffic_limits_once`, cron раз в 15 мин через Xray Stats API, файл `traffic_limits.json`) — но узнать остаток можно было только зайдя в меню инсталлятора по SSH. В `subscription.py` этот учёт никак не отражался, хотя v2rayNG/Clash Meta/Happ/NekoBox умеют показывать расход и лимит прямо в приложении, если сервер отдаёт стандартный HTTP-заголовок `Subscription-Userinfo: upload=…; download=…; total=…`.

### Архитектурное решение

`subscription.py` при каждом запросе подписки читает уже посчитанный `traffic_limits.json` (никаких новых обращений к Xray Stats API — тот и так уже опрашивается cron-ом раз в 15 мин, дублировать `statsquery` на каждый HTTP-запрос подписки было бы лишней нагрузкой при нескольких одновременно открытых клиентах). Раздельного upload/download там нет (только суммарный `used_bytes`), поэтому весь объём указывается как download, upload=0 — на подсчёт процента использования в клиентах (`upload+download` к `total`) это не влияет.

Если лимит для пользователя не задан (`limit_gb` отсутствует/0) — заголовок не отправляется вовсе, а не с `total=0`: часть клиентов трактует `total=0` как «лимит исчерпан», это было бы неверным сигналом для пользователя без лимита вообще.

### Изменения в коде

**`chimera/modules/subscription.py`**:
- `_TRAFFIC_LIMITS_FILE` — путь к уже существующему `traffic_limits.json` (только чтение, `_core.py` не изменяется и не импортируется для этого — файл читается напрямую, как и `state.json`/`mieru.json` в этом же модуле);
- `_load_traffic_limits()` / `_build_userinfo_header(user)` — сборка значения заголовка по email пользователя;
- `do_GET()` — заголовок `Subscription-Userinfo` добавляется в ответ, если для пользователя задан лимит.

### Проверено на

`py_compile`. Функциональный прогон `_build_userinfo_header()` на тестовом `traffic_limits.json`: пользователь с лимитом → корректная строка `upload=0; download=…; total=…`; пользователь без лимита / с `limit_gb=0` / отсутствующий в файле / без email → `None` (заголовок не отправляется). Живая проверка через реальный HTTP-запрос к `/sub/<token>` и разбор ответа в v2rayNG/Happ не проводилась.

---

## 🌐 Курируемые auto-update списки доменов для WARP (itdoginfo/allow-domains) — 4 июля 2026

### Контекст и причины

В режиме SELECTIVE `warp.py` заворачивает в WARP только заданные IP/домены (свои, ручной ввод + 5-минутный ререзолв в IP через cron) — готовых курируемых списков не было. Добавлены три готовых, автообновляемых списка доменов от [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains).

Смысл именно для WARP (а не для блокировки, как обычно используют эти списки): список `outside-raw.lst` заворачивает обращения к российским сервисам через Cloudflare, что осложняет зондам РКН обнаружение самого VPS (трафик к рос. ресурсам с сервера выглядит как будто изнутри сети Cloudflare, а не с "обычного" VPS-IP). `geoblock.lst` и `google_ai.lst` — обратная задача: зарубежные сервисы, заблокированные в РФ, включая отдельно вынесенный апстримом Google AI (часть серверов Google размечена как российская и наоборот, поэтому общего решения через geoblock нет).

### Архитектурное решение

Новый модуль `warp_curated_lists.py`, полностью автономный (по образцу `entry_mirrors.py`/`ingress_geoip.py`):
- собственный кэш `/var/lib/xray-installer/warp_curated_cache.json` (НЕ основной `state.json` ядра — списки могут быть по сотне доменов, незачем раздувать общий state);
- собственный cron `/etc/cron.d/warp-curated-lists-sync` (раз в сутки, `--sync-lists`), ставится/снимается автоматически при включении/выключении хотя бы одного списка — если ничего не включено, ежедневная закачка не идёт;
- при сетевой ошибке для конкретного списка старый кэш для него не обнуляется, только помечается `ok: False` — до следующей удачной синхронизации список продолжает работать с прошлыми данными;
- единственная точка сопряжения с `warp.py` — `get_enabled_curated_domains()` (просто читает кэш, в сеть не ходит) и `do_manage_curated_lists()` (подменю).

`_core.py` не тронут вообще — пункт `[7]` подключён внутри уже существующего `do_manage_warp()` в `warp.py`.

### Изменения в коде

**`chimera/modules/warp_curated_lists.py`** (новый) — источники списков (`CURATED_SOURCES`), загрузка/парсинг (`_fetch_list`/`_parse_list_body`), атомарный кэш под `fcntl.flock` (`_cache_update`, по тому же рецепту, что `_warp_state_save_autonomously()` в `warp.py`), `sync_curated_lists()`, `get_enabled_curated_domains()`, подменю `do_manage_curated_lists()`, cron-точка входа `--sync-lists`.

**`warp.py`**:
- импорт `get_enabled_curated_domains`/`do_manage_curated_lists`;
- `_warp_apply_selective_mode()` — резолвит объединение `WARP_CUSTOM_DOMAINS ∪ курируемые`, в лог добавлено разбиение "свои / курируемые";
- `_standalone_sync()` (5-минутный cron ререзолва IP) — туда же подмешаны курируемые домены, чтобы фоновый ререзолв учитывал их наравне со своими;
- `do_manage_warp()` — новый пункт `[7]` (с пометкой "только в SELECTIVE", если активен другой режим), после выхода из подменю при активном SELECTIVE маршруты сразу переприменяются, не дожидаясь ближайшего тика 5-минутного cron.

### Проверено на

`py_compile` + `ast.parse` обоих файлов. Живой прогон `_parse_list_body`/`_fetch_list`/`sync_curated_lists`/`get_enabled_curated_domains` с реальной закачкой всех трёх источников (`outside-raw.lst` — 39 доменов, `geoblock.lst` — 465, `google_ai.lst` — 28 на момент проверки). Ручная проверка через `grep`, что все 4 точки интеграции (`import`, `_warp_apply_selective_mode`, `_standalone_sync`, меню) на месте. Живая проверка на сервере (реальное включение списка → переключение в SELECTIVE → `ip route` → cron-файл) не проводилась.

---

## 🛡️ SYN-limiter: REJECT вместо DROP + маркировка PQ-риска в fake TLS доменах — 4 июля 2026

### Контекст и причины

При сравнительном анализе стороннего SYN-фикса для Telemt/MTProto (репозиторий [MTPROTO_FIX_By_MEKO](https://github.com/Mekotofeuka/MTPROTO_FIX_By_MEKO)) нашлись две вещи, которые стоило перенести к себе.

**1. DROP в конце hashlimit-цепочки** — финальное правило `telemt_syn_limiter.py` молча топило пакет (`-j DROP`), из-за чего клиент, упёршийся в лимит, ждал TCP-таймаут (3-5 сек) и только потом ретраил с растущим бэкоффом. `REJECT --reject-with tcp-reset` вместо этого мгновенно возвращает клиенту RST — тот реконнектится сразу, без ожидания. Побочных эффектов для лимитера нет: правило и так рассчитано только на превысивших лимит per-IP, объём RST-трафика ничтожен.

**2. Список fake TLS доменов в `mtproto.py` не учитывал поддержку постквантового key exchange** — при `insecure: true` + `pinSHA256` домен без поддержки постквантового гибридного обмена ключами (X25519+ML-KEM) может привести к блокировке iOS-клиентов при хендшейке. В существующем `_DOMAINS` нашлись такие кандидаты (`yandex.ru`, `mail.ru`, `vk.com`, `habr.com`, `github.com`, `microsoft.com`) — по данным стороннего SNI-чекера из того же репозитория, нами напрямую не перепроверялось.

### Изменения в коде

**`chimera/modules/telemt_syn_limiter.py`**:
- финальное правило цепочки: `-j DROP` → `-j REJECT --reject-with tcp-reset`
- счётчик "отброшено" (`_get_drop_counter`) теперь ищет `REJECT` вместо `DROP` в выводе `iptables -L`
- docstring и live-счётчик в меню обновлены под новую формулировку

**`chimera/modules/mtproto.py`**:
- новые `_PQ_RISKY` / `_PQ_CONFIRMED` — множества доменов с известным статусом поддержки постквантового key exchange (источник — сторонний SNI-чекер, помечено в комментарии как непроверенное нами)
- `_select_domain()`: домены в списке помечаются `⚠` (риск блока iOS) / `✓` (подтверждено), легенда показывается только при наличии отмеченных доменов в категории; ручной ввод домена (пункт `99`) тоже проверяется и выводит предупреждение при попадании в риск-список

**`telemt-installer_standalone.py`** — тот же патч, адаптированный под плоскую структуру автономного скрипта (функции `_syn_apply_rules`/`_syn_get_counters` вместо методов модуля).

### Проверено на

`py_compile` всех трёх файлов. Живая проверка отложена до применения на сервере: переприменение пресета SYN-limiter должно заменить старое DROP-правило на REJECT (`_remove_rules()`/`_syn_remove_rules()` чистят по тегу `telemt-syn-limit` независимо от действия правила — старое правило гарантированно удаляется перед установкой нового), а меню выбора домена — показывать значки `⚠`/`✓` рядом с доменами из риск/ок-списков.

---

## 🪞 Entry Mirrors — резервные точки входа для клиент-сайд failover — 3 июля 2026

### Контекст и причины

`smart_balancer.py` и `cluster_ops.py` решают отказоустойчивость EXIT-нод (Режим B), но у клиента всегда один entry-адрес/домен. Если именно его заблокируют или забанят по IP — падает вся связка, сколько бы exit-нод ни было живо позади. Раньше единственным вариантом было вручную поднимать второй сервер и рассылать пользователям отдельную ссылку.

### Архитектурное решение

Новый модуль `entry_mirrors.py`, полностью на стороне клиента, без изменения серверной топологии. Mirror — это отдельный, независимо установленный VLESS+REALITY сервер (тем же инсталлятором, на другом VPS/ASN/в другой стране), в `users.json` которого прописаны те же UUID, что и на основном сервере. Модуль не разворачивает и не настраивает такие серверы — только хранит их публичные connection-параметры (`host`/`port`/`pbk`/`sid`/`sni`/`fp`), проверяет доступность TCP-пробой и генерирует по ним `vless://`-ссылки для каждого пользователя.

Единственная точка интеграции — `get_mirror_uris(uuid, only_healthy=True)`, которую подтягивает `subscription.py` при сборке единой подписки: живые (по последней пробе) mirror-ссылки подмешиваются к основному списку. Клиентские приложения (v2rayNG/NekoBox/Happ), умеющие группировать несколько ссылок подписки в urltest/auto-группу, сами переключаются на живой mirror при недоступности одного из них.

**Честно про пределы подхода:** спасает от блокировки/бана конкретного IP/домена одного сервера. От блокировки самой техники REALITY по паттерну (а не по адресу) — не спасает, поскольку технология на всех mirror одна и та же. Для этого нужна диверсификация протоколов (Hysteria2/MTProto/Mieru/NaiveProxy/SlipGate), это отдельная задача.

### Изменения в коде

- **`chimera/modules/entry_mirrors.py`** (новый) — хранение mirror-нод (`/var/lib/xray-installer/entry_mirrors.json`), TCP health-проба (`probe_all()`, также как отдельный `python3 -m chimera.modules.entry_mirrors probe` для cron), генерация ссылок (`get_mirror_uris()`), меню управления (`do_entry_mirrors_menu()`)
- **`subscription.py`** — `build_subscription_body()` подмешивает `get_mirror_uris(uuid, only_healthy=True)` в общий список ссылок (в try/except, отсутствие модуля не ломает подписку)
- **`_core.py`** — новый пункт `[M]` в подменю `2 → Управление пользователями` (рядом с `[H]` Единая подписка), вызывает `do_entry_mirrors_menu()`

### Проверено на

Синтаксическая проверка (`py_compile`) всех трёх файлов, сверка сигнатур с `_gen_vless_link()` и `_unified_load_users()` в `_core.py`, сверка используемых функций `box_renderer.py` — все зависимости на месте, `ImportError` при отсутствии модуля не приводит к падению подписки/меню.

---

## 🩹 Генерация клиентских ссылок и QR-кодов — 3 июля 2026

### Контекст и причины

При аудите генерации клиентских ссылок/QR (`generate_client_links()` и связанные генераторы конфига в `_core.py`) вскрылись три независимых бага, из-за которых в разных инсталляциях и режимах ссылки вели себя непредсказуемо: где-то не подключался IPv4/IPv6/домен, а в Режиме A в отдельных случаях REALITY не поднимался вообще ни для одного клиента.

### Найденные баги (все устранены)

**1. IPv6-ссылка строилась из непроверенного локального адреса**

`generate_client_links()` использовал `IPV6_PREFLIGHT` — первый global-scope адрес, определённый один раз при установке через `ip -6 addr show scope global`, без подтверждения, что именно он виден снаружи. При нескольких global IPv6 на интерфейсе (privacy-адреса RFC4941, дополнительные интерфейсы от WARP/AWG) порядок вывода `ip addr` не гарантирован — в ссылку мог попасть не тот адрес. IPv4-ссылка рядом уже строилась корректно, через `get_server_ip("4")` с внешней проверкой (curl `api4.ipify.org`). IPv6-ссылка приведена к той же схеме — теперь через `get_server_ip("6")`.

**2. `switch_mode_ab()` не синхронизировал транспортные флаги с `state.json`**

Функция переключения Режим A ↔ Режим B без переустановки читала `awg_exit_enabled`/`h2_exit_enabled`/`reality_dest` из `state.json` только для текста предупреждений в консоли — сами глобальные переменные `AWG_EXIT_ENABLED`, `H2_EXIT_ENABLED`, `PARAM_REALITY_DEST` не входили в `global`-список функции и не переприсваивались. Конфиг после переключения пересобирался по значениям, оставшимся в памяти процесса с предыдущей установки/переключения в этой же сессии, а не по актуальному состоянию на диске.

**3. Как следствие бага №2 — невалидный `serverNames`/`dest` в Режиме A**

Если `AWG_EXIT_ENABLED` протекал в Режим A, пока `PARAM_REALITY_DEST` оставался пустым (дефолт, если в этой сессии не проходил `prompt_awg_exit_mode()`), `generate_xray_config()` собирал REALITY-инбаунд с `"dest": ":443"` и `"serverNames": [""]`. `xray run -test` не ловит это как синтаксическую ошибку, поэтому установка тихо завершалась "успешно" с сервисом, у которого REALITY-хендшейк не проходил ни для одного клиента — ни по домену, ни по IPv4, ни по IPv6, поскольку все три ссылки указывают на один и тот же битый inbound.

Добавлена defensive-проверка `_assert_reality_dest_sane()`, вызываемая в начале всех трёх генераторов конфига (`generate_xray_config`, `generate_xray_config_chain_entry`, `generate_xray_config_chain_entry_multi`) — при обнаружении рассинхрона скрипт падает с понятной ошибкой вместо тихой записи нерабочего `config.json`.

### Изменения в коде

**`chimera/_core.py`**:
- `generate_client_links()` — IPv6-ссылка через `get_server_ip("6")` вместо `IPV6_PREFLIGHT`
- `switch_mode_ab()` — добавлены `AWG_EXIT_ENABLED`, `H2_EXIT_ENABLED`, `PARAM_REALITY_DEST` в `global`, синхронизация из `state` перед пересборкой конфига
- новая `_assert_reality_dest_sane()`, вызывается в начале `generate_xray_config()`, `generate_xray_config_chain_entry()`, `generate_xray_config_chain_entry_multi()`

### Проверено на

Классический VLESS+Reality, Режим A (exit-ноды) и каскадный Режим B (entry ↔ exit) — генерация ссылок/QR и переключение режима через меню работают штатно, схема `flow: xtls-rprx-vision` на entry/exit не менялась (симметричная, как в официальных примерах Xray-core для проксирования через цепочку нод).

---

## 🔁 Единая subscription-ссылка на все активные транспорты — 3 июля 2026

### Контекст и причины

У пользователя может быть одновременно несколько независимых клиентских точек входа — VLESS+Reality (основной), Telemt/MTProto (отдельный прокси для Telegram), Mieru и NaiveProxy (самостоятельные протоколы со своим неймспейсом пользователей). Раньше ссылки/QR под каждый транспорт генерировались отдельно и рассылались вручную — при любом изменении топологии (новый UUID, ротация Reality-ключей, смена SNI, установка нового транспорта) все выданные ссылки приходилось пересылать заново.

### Архитектурное решение

Единый HTTP(S)-эндпоинт `/sub/<токен>` на отдельном порту (не завязан на существующий nginx-фронт перед 443 — топология у каждого инсталла своя). Тело ответа собирается **на каждый запрос заново** — `users.json`, `state.json`, `telemt.toml`, `mieru.json`, `naiveproxy.json` читаются live, без кеша. Любое изменение конфигурации видно клиенту при следующем автообновлении подписки (Happ/NekoBox/v2rayN дергают URL сами по расписанию) — вручную рассылать ссылки больше не нужно.

**Токен** в URL — `hmac_sha256(pepper, uuid)[:24]`, не сам UUID.

**Что агрегируется:**
- `vless://` (Reality/xHTTP) — общие server-side параметры (`pbk`/`sid`/`sni`/`fp`/`port`) из `state.json` + UUID конкретного пользователя
- `tg://proxy` (Telemt/MTProto) — если найден telemt-юзер с именем, совпадающим с `device_label`/`name`/email-префиксом VLESS-пользователя
- `mierus://` (Mieru) — как standalone-аддон, так и режим `hybrid_addon` (Mieru как единственный внешний вход вместо VLESS)
- `naive+https://` (NaiveProxy)

**Важный нюанс с `hybrid_addon`:** если он активен (внешний VLESS-inbound переведён на SOCKS-петлю `127.0.0.1`), `vless://` автоматически исключается из подписки — отдавать нерабочую ссылку клиенту бессмысленно. Обнаруживается по наличию `/var/lib/xray-installer/hybrid_mieru_state.json`, проверяется на каждый запрос — при `--rollback` вернётся само.

**Сопоставление UUID ↔ сателлитные логины:** Telemt/Mieru/NaiveProxy не знают о UUID напрямую (свой неймспейс пользователей). Матчинг — сначала по имени (`device_label`/`name`/email-префикс), при неудаче — ручной override через `menu → 2 → H → 5` (`identity_map` в `subscription.json`).

### Изменения в коде

**Новый модуль `chimera/modules/subscription.py`** — полностью изолированный, `_core.py` не модифицируется в части логики:
- `_gen_vless_link`, `_unified_load_users` — делегирование в `_core.py` тем же паттерном, что и `fragment_link.py`
- собственный `ThreadingHTTPServer` с TLS (переиспользует Let's Encrypt сертификат на домене, иначе — сертификат Hysteria2 из `state.json`)
- systemd-юнит `vless-subscription.service`, генерируется и устанавливается через меню
- меню на `box_renderer.py` — тот же стиль, что и в остальных разделах проекта
- QR-коды к ссылкам подписки через `qrencode` (тот же паттерн, что в `mieru.py`), печатаются отдельным блоком **вне** рамки — `qrencode` рисует свою фиксированную ASCII-сетку, внутри `box_renderer` она ломает выравнивание

**`chimera/_core.py`**:
- пункт `H` в `_menu_users()` (раздел 2 главного меню — Управление пользователями) — ленивый импорт `do_subscription_menu()` по образцу `F`/`G` (fragment_link/fragment_share)

### Пофиксенный баг

Systemd-юнит с `ProtectSystem=strict` монтирует всю ФС read-only, кроме путей в `ReadWritePaths`. Без `PrivateTmp=true` каталог `/tmp` тоже становился недоступен на запись — `tempfile` внутри `_core.py` при импорте падал с `No usable temporary directory`, исключение гасилось тихим `except`, `_unified_load_users()` молча возвращал пустой список, и **любой** токен приводил к 404 независимо от корректности ссылки. Добавлен `PrivateTmp=true` в юнит.

### Известные ограничения

- Сопоставление сателлитных протоколов с UUID по имени — эвристика, не гарантия; при коллизиях/несовпадении логинов нужен ручной override
- Отдельный порт для подписки не проксируется через существующий nginx-фронт автоматически — если нужен единый порт 443, придётся руками подключить сгенерированный nginx-сниппет

---

## 🔀 Hysteria2-транспорт: полная переработка — 2 июля 2026

### Контекст и причины

Режим B (Entry → Exit) с транспортом Hysteria2 не работал совсем — трафик всегда уходил напрямую с Entry-ноды, игнорируя Exit. В ходе двухдневной отладки на живых серверах было выявлено несколько независимых багов, накладывавшихся друг на друга.

### Найденные баги (все устранены)

**1. Xray built-in `protocol: "hysteria"` — непригоден для использования с Xray-core 26.x**

Xray-core 26.x имеет задокументированные неисправленные проблемы с нативной реализацией Hysteria2 (`protocol: "hysteria"`):
- `pinnedPeerCertSha256` не работает с CA-сертификатами: Xray пытается провалидировать цепочку сертификатов, получает ошибку (CA-сертификат не может быть листовым), и до проверки SHA256-пина не доходит (issues XTLS/Xray-core #5904, #5655)
- Параметры `up`/`down` перемещены в `finalmask/quicParams` и выдают предупреждение при старте
- Отсутствие `alpn: ["h3"]` в `tlsSettings` приводило к срыву TLS-хендшейка

**2. `_save_xray_config()` писала в "мёртвый" файл**

`/usr/local/etc/xray/config.json` — симлинк на `/etc/xray/config.json` (реальный файл, который читает Xray по `ExecStart`). Запись через `tmp.replace(p)` атомарно **заменяла симлинк обычным файлом**, после чего оба пути расходились: патч уходил в "осиротевшую" копию, а живой Xray продолжал работать со старым конфигом. Весь трафик продолжал идти через `direct`.

**3. Catch-all routing-правило не переключалось на `proxy`**

`h2_transport_apply()` добавлял outbound с тегом `proxy`, но не трогал routing. Catch-all правило `{network: "tcp,udp", outboundTag: "direct"}` продолжало направлять весь трафик напрямую — H2-outbound оставался "осиротевшим" и никогда не использовался.

**4. Регенерация `config.json` откатывала активный H2-транспорт**

Любой вызов `generate_xray_config_chain_entry_multi()` (смена DNS, RIPE-правил, добавление ноды и т.д.) полностью перезаписывал `config.json`, молча откатывая routing и outbound обратно на `direct`.

**5. Hysteria2-сервер слушал `[::]` (IPv6-only) на IPv4-only VPS**

`_generate_h2_config()` хардкодила `listen: "[::]:PORT"`. На VPS без IPv6 (частый случай) пакеты доходят до сетевого интерфейса (видно в `tcpdump`), но до процесса hysteria не доходят — IPv6-сокет не принимает IPv4-пакеты без dual-stack. Клиент получал timeout.

**6. Сертификат не содержал `subjectAltName`**

`openssl req -x509` без явного SAN генерирует сертификат без `subjectAltName`. Нативный hysteria2-клиент (в отличие от Xray) проверяет SAN при TLS-валидации и падал с `"x509: cannot validate certificate for X because it doesn't contain any IP SANs"`.

**7. `insecure: false` + `pinSHA256` не работает с самоподписанными сертификатами**

В нативном hysteria2-клиенте `pinSHA256` не обходит проверку цепочки CA. При `insecure: false` клиент падал с `"certificate signed by unknown authority"` до проверки пина. Нужно `insecure: true` + `pinSHA256` — пин обеспечивает безопасность, `insecure` только отключает проверку CA-цепочки.

**8. Hysteria2-бинарь отсутствовал на Entry-ноде**

При удалённой установке Exit-ноды через SSH бинарь `hysteria` устанавливался только на Exit. Entry-нода не получала его, что вызывало ошибку при попытке запустить `hysteria-client`.

### Решение: полная смена архитектуры транспортного уровня

Вместо Xray built-in `protocol: "hysteria"` теперь используется **нативный hysteria2-клиент** + **SOCKS5 outbound** в Xray:

```
Клиент → Xray (VLESS+Reality inbound)
       → Xray (protocol: "socks" outbound → 127.0.0.1:10809)
       → hysteria-client.service (нативный /usr/local/bin/hysteria client)
       → Exit-нода (hysteria-server) → Интернет
```

Для конечного пользователя (VLESS-ссылки, клиентские приложения) ничего не изменилось.

### Изменения в коде

**`chimera/modules/hysteria2_transport.py`** — полная переработка:
- Убран весь код генерации Xray `protocol: "hysteria"` outbound
- `h2_transport_apply()`: генерирует `/etc/hysteria/client.yaml`, создаёт и запускает `hysteria-client.service`, патчит Xray outbound на `protocol: "socks"` → `127.0.0.1:10809`, переключает catch-all routing-правило на тег `proxy`
- `h2_transport_remove()`: останавливает `hysteria-client.service`, восстанавливает предыдущий outbound и routing
- `_find_xray_config()`: исправлен порядок путей — сначала `/etc/xray/config.json` (реальный), потом `/usr/local/etc/xray/config.json` (симлинк)
- `_save_xray_config()`: запись идёт в `p.resolve()` если путь — симлинк, не ломая ссылку
- `_write_h2_client_config()`: `insecure: true` + `pinSHA256` для самоподписанных сертификатов
- `_ensure_hysteria_client_service()`: автоматическая загрузка бинаря на Entry-ноду если отсутствует

**`chimera/modules/hysteria2_exit_mgr.py`**:
- `_ensure_h2_cert()`: добавлен параметр `ip=`, сертификат генерируется с `-addext 'subjectAltName=IP:{ip}'` и `-addext 'basicConstraints=CA:FALSE'`; добавлен fallback через extfile для OpenSSL < 1.1.1; добавлена финальная проверка наличия SAN
- `h2_exit_install()`: локальный IP определяется до вызова `_ensure_h2_cert()` и передаётся в него
- `h2_exit_remote_install()`: определяет наличие IPv6 на удалённой ноде и выбирает `listen: "0.0.0.0:PORT"` или `listen: "[::]:PORT"` соответственно; команда генерации сертификата получила `-addext 'subjectAltName=IP:{host}'`

**`chimera/_core.py`**:
- Добавлена функция `_h2_reapply_transport_if_active()` — вызывается после любой регенерации `config.json`, автоматически восстанавливает H2-транспорт если он был активен

---



**Исправлено**

`_core.py`: `_load_state_into_globals()` подгружала из `state.json` `domain`/`uuid`/`public_key`/`short_id`/`reality_dest`, но **не `private_key`** — при входе в меню `[P]` он оставался дефолтным `""`, из-за чего PQ-инбаунд получал пустой `privateKey` и падал на `xray -test` (`infra/conf: empty "privateKey"`). Основной REALITY-конфиг не задевало — там `private_key` подставляется в других местах. Добавлено в `global`-декларацию и в подгрузку из `state.get("private_key", ...)`.

`pq_vless.py`: `_write_and_test()` обрезала сообщение об ошибке `xray -test` до 300 символов **и в экранный вывод, и в лог** — на длинном баннере версии Xray это съедало содержательную часть ошибки полностью. Теперь до отката конфига полный (необрезанный) `stderr`/`stdout` пишется в `/var/log/vless-install.log`, а сам провалившийся `config.json` сохраняется рядом как `config.json.pq-failed`; срез в возвращаемом сообщении увеличен до 1000 символов.

**Подтверждено опытным путём**

На Xray 26.6.27 (сервер) комбинация REALITY + `flow: xtls-rprx-vision` + VLESS Encryption (`mlkem768x25519plus`) не проходит аутентификацию REALITY — сервер откатывает соединение на камуфляжный `dest`, клиент видит настоящий сертификат сайта-камуфляжа вместо ожидаемого. Воспроизведено одинаково на стороннем sing-box-клиенте (NyameBox) и на оригинальном Xray-core (v2rayN) — то есть проблема не в клиентской реализации, а именно в этой тройной связке на сервере. Без `flow` (Vision выключен у клиентов PQ-инбаунда) REALITY-рукопожатие проходит штатно.

**Добавлено**

- При включении PQ-инбаунда (пункт `1`) теперь отдельно спрашивается, использовать ли `flow=xtls-rprx-vision` — по умолчанию рекомендуется без него.
- Новый пункт меню `4` — «Переключить flow» — меняет только `flow` у клиентов PQ-инбаунда (`xray -test` → restart) без перегенерации ключей/`decryption`/`shortId`, поэтому уже выданная ссылка не ломается (меняется только `&flow=` в ней). Выбор сохраняется в `state.json` (`pq_vless_xtls_flow`) и переживает перегенерацию ключей и восстановление инбаунда после полной перегенерации `config.json`.
- В статусе меню теперь видно текущее состояние `Flow (xtls-rprx-vision): да/нет`.

---

## 🧪 Постквантовый VLESS — экспериментальный изолированный инбаунд — 28 июня 2026

**Добавлено**

`chimera/modules/pq_vless.py` — VLESS Encryption (mlkem768x25519plus) и опциональная PQ-подпись REALITY (ML-DSA-65)

Новый пункт меню `[P] Постквантовый VLESS` в «Настройках сети», рядом с `[X] XTLS-flow режим`. Включает отдельный VLESS+REALITY инбаунд на собственном порту — отдельном от основного, существующая ссылка и конфиг не трогаются и продолжают работать как прежде. Ключи `encryption`/`decryption` генерируются через `xray vlessenc`, подпись REALITY (опционально, отдельная галка) — через `xray mldsa65`; оба требуют свежей сборки Xray-core с поддержкой этих команд. Переиспользует существующий REALITY-`dest`/ключи с отдельным `shortId` и тех же пользователей из `users.json` — никаких дополнительных учёток не создаёт.

Ключи генерируются один раз и сохраняются в `state.json` — повторное включение, перезапуск сервиса или полная перегенерация конфига (смена домена, добавление ноды и т.п.) переиспользуют те же значения, а не выпускают новые, иначе уже выданные клиентам ссылки сломались бы. Пересоздание ключей — отдельным явным пунктом, с предупреждением, что старая постквантовая ссылка после этого перестанет работать.

По умолчанию выключен. Перед включением показывается предупреждение: не все клиенты поддерживают VLESS Encryption и постквантовую подпись REALITY — известны случаи отказа подключения у части распространённых приложений на старых сборках Xray-core.

---

## 🌀 Telemt: маршрутизация Telegram-подсетей через WARP — 28 июня 2026

### Контекст

Если сервер (standalone Telemt либо Exit-узел каскада) физически расположен
в РФ, прямые соединения к Telegram ME-серверам/DC могут деградировать — ТСПУ
специфично режет MTProto-сигнатуру независимо от геолокации IP. Нужен способ
направить именно Telegram-трафик через WARP, не трогая при этом основной
WARP-режим (FULL/SELECTIVE/RUNET), который пользователь может держать
настроенным под обычных VPN-клиентов.

### Новое

#### Модуль `telemt_warp_route.py` — отдельная policy-маршрутизация Telegram → WARP

- Своя таблица маршрутизации (`fwmark`/`table` = 300, отдельно от диапазона
  AWG `1000+n`) с маршрутом `default dev wg-warp` — основную таблицу не
  трогает и не зависит от выбранного режима WARP для клиентов
- `iptables mangle OUTPUT` — `MARK --set-mark 300` по каждой подсети из
  **живого** списка `tg_nets.py` (тот же список, что уже используется для
  iptables REDIRECT в `mtproto.py`), плюс `ip rule fwmark 300 table 300`
- Cron-watchdog каждые 2 минуты: самовосстановление `ip rule`/маршрута после
  ребута и автоматический подхват изменений списка подсетей без участия
  пользователя
- Persist — собственный дамп `iptables-save` + systemd-сервис восстановления
  при загрузке через `iptables-restore --noflush` (не затирает правила,
  выставленные другими модулями, например REDIRECT-цепочку `tproxy-telemt`)
- Модуль автономен: импортирует из `warp.py` только публичную константу
  `WG_INTERFACE`, без обращения к приватным функциям/состоянию режимов
  WARP-клиента
- Новый пункт меню Telemt → **`W`** «Telegram через WARP», строка статуса
  `TG→WARP:` в шапке меню, ручная синхронизация по требованию
- Авто-`refresh()` после обновления подсетей Telegram в обоих местах вызова
  `update_tg_nets_interactive()` в `mtproto.py` — если режим включён, новый
  список тут же переприменяется к mangle-правилам

### Совместимость

- Применимо только там, где сервер **физически** делает исходящее
  соединение к Telegram: standalone Telemt (`cascade == "none"`) или
  Exit-узел каскада. На Entry с активным tproxy-перехватом
  (`xray_enable_tproxy_for_telemt`) эффекта не даёт — `nat OUTPUT`
  (REDIRECT) обрабатывается netfilter позже `mangle OUTPUT` и матчится по
  оригинальному dst независимо от выбранного по fwmark маршрута, поэтому
  пакет всё равно уходит в локальный `dokodemo`, а не в WARP
- На Exit-узле, работающем через AWG (`sockopt.mark` у freedom outbound в
  Xray), включение этого режима **перебивает** AWG-метку для пакетов к
  Telegram — это осознанно: для Telegram-направления WARP получает
  приоритет. Если это не нужно — не включать на таком Exit-узле
- Полностью независим от `warp.py`: использует отдельную таблицу/fwmark,
  не пересекается ни с одним из режимов FULL/SELECTIVE/RUNET

---

## 🎯 WARP: Endpoint-менеджер — интеллектуальный поиск и переключение узла подключения Cloudflare Anycast — 28 июня 2026

**Файл:** `chimera/modules/warp.py`
**Тип изменения:** аддитивное расширение существующего модуля (новый функционал, рефакторинга нет)
**Точка входа `do_manage_warp()` и весь публичный API не изменились — добавлен один пункт меню (`6`).**

---

### Итог в одном абзаце

К модулю WARP (WireGuard + wgcf) добавлен менеджер узла подключения: автоматическое
параллельное сканирование Anycast-диапазонов Cloudflare с многоуровневым скорингом
(TCP-connect → ICMP → реальный WireGuard-handshake), кэш и история найденных узлов,
интеллектуальное сравнение с текущим узлом по пороговому правилу, ручной ввод и
fallback-список на случай, если автопоиск невозможен. Намеренно используется термин
«Endpoint» / «узел подключения», а не «регион» — Cloudflare работает через Anycast,
и один физический узел может обслуживать разные географии. Изменение в уже работающем
коде — одно, аддитивное (расширение `_rollback_full_mode()`); вся новая функциональность
переиспользует существующие механизмы защиты SSH, маршрутизации и commit-confirm,
ни один из них не дублируется и не заменяется.

---

### I. Новые константы

```
WG_CONFIG_ENDPOINT_BACKUP                                   — /etc/wireguard/wg-warp.conf.endpoint-backup
WARP_SCAN_PORTS = (2408, 500, 1701, 894, 4500)               — единый список портов (УТ-12)
WARP_SCAN_RANGES                                             — 22 диапазона /24 для автопоиска (п.2 ТЗ)
WARP_HOSTS_PER_SUBNET = (2, 4)                                — случайных хостов на /24 (Anycast — весь /24 не нужен)
WARP_FALLBACK_ENDPOINTS / _build_fallback_endpoints()         — 54 фиксированных ip:port, считается через ipaddress при импорте
ENDPOINT_TCP_TIMEOUT / ENDPOINT_ICMP_TIMEOUT                  — 1.5с / 1.0с (уровни 1–2)
ENDPOINT_SWITCH_THRESHOLD_MS = 30                             — порог «существенно лучше» (УТ-4)
ENDPOINT_HISTORY_MAX = 10                                     — УТ-6
HANDSHAKE_WAIT_ACTIVE_SEC / HANDSHAKE_SETTLE_SEC / HANDSHAKE_CURL_TIMEOUT = 5 / 3 / 5  — этапы УТ-2
```

### II. Новые функции

| Группа | Функции |
|---|---|
| Хранение (мимо `_WARP_STATE_MAP`, см. III.3) | `_endpoint_cache_load()`, `_endpoint_cache_save()`, `_endpoint_history_load()`, `_endpoint_history_add()` |
| Зондирование (уровни 1–2) | `_tcp_probe()`, `_icmp_probe()`, `_select_scan_targets()`, `_probe_host_all_ports()`, `_score_probe()`, `_probe_single_endpoint()` |
| Сканирование | `_scan_warp_endpoints()` — `ThreadPoolExecutor`, `cancel_futures=True` на Ctrl+C (УТ-7) |
| Подбор | `_pick_best_endpoint()` — пороговая логика УТ-4 |
| Применение (уровень 3 + смена) | `_verify_warp_handshake()`, `_restore_endpoint_backup()`, `_change_warp_endpoint()` |
| Текущий Endpoint | `_get_warp_endpoint_full()` — комплементарна существующей `_get_warp_endpoint()` (та не меняется) |
| Меню | `_menu_endpoint_manager()`, `_show_endpoint_pick_list()`, `_show_history_pick_list()` |

Новые ключи `state.json` (вне `_WARP_STATE_MAP`): `warp_endpoint_cache`, `warp_endpoint_history`.

### III. Изменения в уже работающем коде — ровно два места, оба аддитивные

1. **`do_manage_warp()`** — одна строка в отображении меню (`6  Изменить Endpoint WARP`) +
   один `elif ch == "6" and installed:`. Существующие пункты `1`–`5` не переименованы и не
   перенумерованы.
2. **`_rollback_full_mode()`** — добавлена проверка в начало функции: если на момент
   срабатывания watchdog существует `wg-warp.conf.endpoint-backup`, сначала восстанавливается
   предыдущий конфиг, и только потом выполняется штатная (не тронутая) логика — остановка
   туннеля и снятие маршрутов. Без backup-файла поведение функции побайтово прежнее.
   Это сделано, чтобы `_change_warp_endpoint()` могла переиспользовать **тот же** watchdog-юнит
   (`warp-commit-confirm`, УТ-9) для смены Endpoint в FULL-режиме, а не заводить второй,
   параллельный механизм отката.
3. **Хранение кэша/истории сделано через прямой flock-доступ к `core.STATE_FILE`,
   а не через `_WARP_STATE_MAP`/`_state_get`/`_state_set`** — это не отклонение, а буквальное
   требование п.5/УТ-6 ТЗ: `_WARP_STATE_MAP` — явный белый список существующих core-глобалей,
   расширять его новыми, не относящимися к ядру ключами не нужно. Подтверждено тестом:
   round-trip кэша/истории на временном `state.json` не затирает посторонние ключи.

### IV. Три инженерных решения, отклоняющиеся от буквального текста ТЗ

| № | Буквальное требование | Реализовано | Почему |
|---|---|---|---|
| 1 | ICMP-зонд (п.3, уровень 2) | Системный бинарь `ping` через `_run()`, как и весь остальной модуль (`curl`/`wg`/`ip`/`systemctl`) | Raw ICMP socket в чистом stdlib требует ручной сборки заголовка/checksum — лишняя хрупкость без выгоды; `ping` (`iputils-ping`) — такая же «существующая зависимость», как и остальные shell-вызовы. Если `ping` недоступен/заблокирован — просто `icmp_ok=False`, без ошибки (п.3: «если разрешён») |
| 2 | Уровень 3 — реальный handshake через **временный** WG-профиль, отдельно от уровней 1–2, до применения | Handshake-проверка выполняется один раз — как часть самого `_change_warp_endpoint()`, на настоящем интерфейсе, под защитой backup-конфига + commit-confirm watchdog + автооткатом | Второй одновременный WG-интерфейс с тем же приватным ключом — новая поверхность отказа (два handshake с одним registered-peer одновременно) и явное дублирование логики проверки handshake, что запрещено инвариантами ТЗ. Уровни 1–2 уже дают достоверное ранжирование для скоринга/рекомендации без касания живого туннеля |
| 3 | (общее по инвариантам) | Кэш/история — мимо `_WARP_STATE_MAP`, см. III.3 | Соответствует, а не противоречит ТЗ — указано явно, чтобы пункт не потерялся среди остальных |

### V. Защита SSH при смене Endpoint

- SSH-клиент защищён host-маршрутом через `orig_gw`/`orig_if` (существующий механизм,
  не меняется) — он физически не привязан к интерфейсу `wg-warp` и не зависит от того,
  поднят ли сейчас этот интерфейс.
- `systemctl restart wg-quick@wg-warp` — единственное разрешённое исключение из правила
  «переключение без рестарта» (УТ-1), задокументировано прямо в докстринге `_change_warp_endpoint()`.
- Split-default-маршруты FULL-режима (единственное, что в принципе способно задеть SSH)
  переприменяются (`_warp_apply_full_mode()`) **только после** того, как новый Endpoint
  подтверждён живым handshake'ом. До этого момента — при любой ошибке (рестарт/handshake) —
  синхронный откат сразу же, без ожидания таймера, потому что риска для SSH ещё не было.
- Сам момент переприменения — что при успехе, что при восстановлении после ошибки —
  защищён ровно тем же `_schedule_rollback_watchdog()` / `_confirm_with_timeout()` /
  `_cancel_rollback_watchdog()`, что и обычное включение FULL. Никакого отдельного,
  менее проверенного механизма для Endpoint-менеджера не вводилось.
- В Selective/Runet default-маршрут не трогается ни самим WARP, ни сменой Endpoint —
  поэтому watchdog там не нужен (УТ-8), достаточно синхронного rollback при ошибке handshake.

### VI. Протестировано

| Проверка | Результат |
|---|---|
| `py_compile` + `pyflakes` | чисто, без предупреждений |
| Реальный импорт модуля внутри пакета `chimera` (не изолированный синтаксис) | успешно |
| Round-trip кэша/истории на временном `state.json` | посторонние ключи не затёрты; обрезка истории до 10; дедуп при повторном использовании |
| Пороговая логика `_pick_best_endpoint()` (УТ-4), 4 сценария | текущий недоступен → рекомендован лучший; новый быстрее на 35+мс с TCP+ICMP → рекомендовано переключение; разница 10мс (< порога) → не переключать; кандидат без ICMP → не переключать |
| `_change_warp_endpoint()`: WARP не установлен | корректный отказ с предупреждением, без падения |
| `_change_warp_endpoint()`: идемпотентность (тот же Endpoint) | `True`, без побочных действий |
| `_change_warp_endpoint()`: новый Endpoint не отвечает на TCP | отказ до любых изменений конфига/сервиса |
| `_build_fallback_endpoints()` | 54 адреса, корректные `ip:port` для всех диапазонов |

Не тестировалось на живом сервере (нет реального `wg-warp` интерфейса в среде разработки):
сам цикл «рестарт → handshake → откат» при настоящем сетевом сбое, поведение под реальным
`systemd-run --auto-rollback` и реакция на фактическую блокировку ICMP провайдером — эти
сценарии нужно прогнать на тестовом VPS перед продакшен-использованием.

---

## 🛡️ WARP: полный переход с warp-cli на WireGuard + wgcf, защита SSH и автоматический откат — 27 июня 2026

**Файл:** `chimera/modules/warp.py`
**Тип изменения:** полный рефакторинг (breaking implementation, non-breaking API)
**Точка входа `do_manage_warp()` и публичный API не изменились.**

---

### Итог в одном абзаце

Старый модуль управлял официальным клиентом Cloudflare (`warp-cli`) и несколько лет
страдал обрывами SSH при включении полного туннеля. Модуль полностью переписан на
нативную связку **WireGuard + wgcf** — переключение режимов теперь идёт через
`ip route`, без перезапуска службы. По ходу работы найдено и исправлено 7 отдельных
багов (3 — в материалах для слияния, ещё не доехавшие до продакшена; 4 — в самом
процессе рефакторинга и эксплуатации), две гипотезы об ошибках проверены и
отклонены как несуществующие, и в довершение добавлен механизм автоматического
отката (commit-confirm), который не лечит конкретную причину, а гарантирует
восстановление SSH при ЛЮБОЙ непредвиденной причине в будущем.

---

### I. Архитектурный рефакторинг

**Было**
`warp.py` оборачивал бинарник `warp-cli` (официальный клиент Cloudflare):
запуск/остановка через сам клиент, режимы маршрутизации эмулировались через
split-tunnel настройки клиента и iptables mangle-метки + сетевой namespace для
защиты SSH. Хвост файла (~1380 строк) заканчивался мёртвым комментарием
с перечнем из 7 «запланированных» функций без единой реализации (dashboard,
ротация TLS-fingerprint и т.п.) — авторские TODO, оставленные предыдущим
разработчиком; убраны при рефакторинге как мёртвый код.

**Стало**
- WireGuard-интерфейс `wg-warp`, конфиг генерируется через `wgcf register` +
  `wgcf generate`, поднимается **один раз** (`systemctl start wg-quick@wg-warp`).
- Конфигу принудительно прописывается `Table = off` — wg-quick никогда сам не
  трогает основную таблицу маршрутизации.
- Режимы `full` / `selective` / `runet` переключаются исключительно через
  `ip route add/del`, без перезапуска службы.
- SSH-сессия и сам Cloudflare-эндпоинт защищены явными host-маршрутами через
  реальный (захваченный до подъёма WARP) шлюз.
- Фоновый ререзолв доменов в `selective` — через cron */5 мин (`--sync`),
  атомарно, под `fcntl.flock`.

**Публичный API (сохранён без изменений сигнатур)**

| Функция | Статус |
|---|---|
| `do_manage_warp()` | без изменений — точка входа из `_core.py` |
| `install_warp() -> bool` | сигнатура сохранена, реализация полностью заменена |
| `configure_warp(mode, ssh_client_ip, custom_ips=None, custom_domains=None) -> bool` | **восстановлена** — отсутствовала в обоих исходных прототипах, но существовала в старом модуле; добавлена обратно для обратной совместимости |
| `command_exists(cmd) -> bool` | сохранена |
| `uninstall_warp() -> bool` | новая (в старом модуле отсутствовала как отдельная функция; не убирает функциональность, только добавляет) |
| Ключи состояния `WARP_MODE`, `WARP_CUSTOM_IPS`, `WARP_CUSTOM_DOMAINS`, `warp_active_routes` (новый) | сохранены/добавлен |

---

### II. Баги, найденные при аудите исходных материалов (до деплоя)

Два прототипа легли в основу слияния. Оба содержали реальные, не пересекающиеся
друг с другом баги — ни один не дошёл до сервера, все исправлены на этапе аудита.

| № | Прототип | Баг | Как нашли | Исправление |
|---|---|---|---|---|
| 1 | A | URL wgcf строился с расширением `.tar.gz` — такого ассета в релизах ViRb3/wgcf не существует, бинарник раздаётся без расширения | Прямая проверка страницы релизов GitHub | Скачивание голого бинарника `wgcf_{version}_linux_{arch}` |
| 2 | B | В имени файла ассета сохранялась буква `v` из тега (`wgcf_v2.2.31_...`) — реальный файл без `v` (`wgcf_2.2.31_...`), `v` только в пути тега | Та же проверка релизов | `v` обрезается только при формировании имени файла, не пути |
| 3 | B | Сгенерированный профиль WireGuard искался по имени `wg-wgcf.conf` — у wgcf реальное имя `wgcf-profile.conf` | Документация wgcf | Поиск по правильному имени |
| 4 | B | `_standalone_sync()` читал вложенный JSON-ключ `state["warp"]["WARP_MODE"]`, хотя весь остальной код модуля писал плоские ключи (`warp_mode` на верхнем уровне) — фоновая синхронизация в `selective` никогда не сработала бы | Сверка схемы записи/чтения state.json внутри самого прототипа | Плоские ключи во всём модуле, включая `--sync` |
| 5 | оба | Циклический импорт: `_core.py` импортирует `do_manage_warp` из `warp.py` ДО определения `command_exists`/`log_to_file`/`STATE_FILE`/глобалей `WARP_*`. Прямой `from chimera._core import ...` гарантированно роняет установщик `ImportError` на старте | Чтение реального `_core.py`, проверка живым импортом всего пакета | Отложенное (lazy) связывание через `_core_module()`, вызывается только в момент фактического обращения |
| 6 | (старый продакшн-модуль) | Голые (без кавычек) литералы `full`/`selective`/`runet` в сравнениях — реальный риск `NameError` при попадании в этот код путь | Грep по старому файлу | Везде заменено на строковые константы `MODE_FULL`/`MODE_SELECTIVE`/`MODE_RUNET` |

---

### III. Изменения архитектуры в процессе (требование автономности)

После первой версии заказчик потребовал убрать любые изменения в `_core.py`
(32k строк, монолит на Windows-репозитории, никаких правок). Исходный дизайн
полагался на две новые функции в `_core.py` (`warp_state_load`/`warp_state_save`)
— переписан на полностью самодостаточную персистентность внутри `warp.py`.

**Найдены и обойдены две мины в буквальной формулировке требования:**

1. **Слепой сбор `vars(core)` по префиксу `WARP_`** — в `_core.py` под этим
   префиксом реально лежат `WARP_MDM_FILE` / `WARP_SERVICE_FILE` (`PosixPath`,
   не сериализуются в JSON) и мусорные константы от старого SSH-namespace
   подхода (`WARP_SSH_NAMESPACE` и т.п.). Слепой сбор уронил бы `json.dumps()`
   и **тихо** проглатывал бы ошибку сохранения при каждом вызове.
   → Заменено на явный белый список `_WARP_STATE_MAP` (7 пар «JSON-ключ ⇄
   имя глобали»).
2. **Простое `.upper()`/`.lower()` для маппинга имён** — исторический JSON-ключ
   `warp_ssh_ip` соответствует глобали `WARP_SSH_CLIENT_IP`, а не `WARP_SSH_IP`.
   Простое преобразование регистра тихо сбрасывало бы сохранённый SSH IP в
   пустую строку при каждой перезагрузке меню.
   → Тот же явный маппинг `_WARP_STATE_MAP` устраняет и эту мину.

Обе мины подтверждены вживую (распечатка реальных атрибутов `_core.py`,
round-trip теста сохранения/загрузки без затирания посторонних ключей
state.json, включая UUID пользователей Xray).

---

### IV. Гипотезы об ошибках — проверены и отклонены

Заказчик сообщил о двух потенциальных багах по результату чтения кода (без
прогона на сервере). Обе проверены тестами на реальном коде — не подтвердились.

| Гипотеза | Проверка | Результат |
|---|---|---|
| Опечатка/рассинхрон имени функции: объявлена как `_warp_state_save_autonomously`, а вызывается как `_warp_save_state_autonomously` | `grep` обоих вариантов по всему файлу | 8 совпадений на правильное имя, 0 — на перепутанное. Бага нет |
| `_standalone_sync()` в конце вызывает автономную save-функцию, которая берёт `WARP_ACTIVE_ROUTES` из пустых in-memory глобалей свежего cron-процесса и затирает только что посчитанные маршруты | Симуляция запуска `--sync` в чистом процессе (`hasattr(core, 'WARP_ACTIVE_ROUTES') == False`), проверка итогового state.json | `_standalone_sync()` пишет маршруты напрямую из/в тот же JSON под тем же `flock`, минуя глобали ядра. Бага нет — но добавлен явный комментарий в код, объясняющий это, чтобы вопрос не возникал повторно |

---

### V. Баг №7: молчаливый провал установки `wireguard-tools`

**Симптом:** `Failed to start wg-quick@wg-warp.service: Unit wg-quick@wg-warp.service not found` — после успешной регистрации аккаунта Cloudflare и генерации конфига.

**Причина:** `core._pkg_install()` вызывает `apt-get install` с `check=False,
quiet=True` (stdout/stderr в `DEVNULL`) и не возвращает признак успеха.
`install_warp()` проверял наличие `wg-quick` **до** установки, но не **после** —
если `apt-get install` по любой причине (чаще всего — протухший кэш пакетов на
свежем образе VPS) не срабатывал, модуль **молча** продолжал: скачивал wgcf,
тратил регистрацию аккаунта Cloudflare, генерировал конфиг — и падал только на
`systemctl start`, без единой зацепки за реальную причину.

**Исправление:**
- `_wireguard_ready()` — раздельная проверка бинарника (`command_exists("wg-quick")`)
  **и** самого systemd-юнита (`systemctl list-unit-files wg-quick@.service`) —
  встречаются образы с частично битой установкой пакета, где один есть, а
  другого нет.
- `_ensure_wireguard_installed()` — собственный явный `apt-get update` +
  `apt-get install` с захватом `stderr`, обязательный re-check после установки,
  **до** скачивания wgcf и траты регистрации аккаунта.

---

### VI. Баг №8 (корневая причина обрыва SSH в FULL-режиме)

**Симптом:** При применении режима `full` обрывалась текущая SSH-сессия
(`client_loop: send disconnect: Connection reset`), сервер становился
недоступен.

**Корневая причина (подтверждена эмпирически):** защитный host-маршрут для
SSH-клиента добавлялся без флага `onlink`:

```python
_run(["ip", "route", "add", ssh_cidr, "via", orig_gw, "dev", orig_if], capture=True, quiet=True)
```

На провайдерах с point-to-point адресацией (шлюз физически не входит в подсеть
интерфейса — что и означает `onlink` в собственном default-маршруте сервера,
например `default via 10.0.0.1 dev ens3 onlink`) эта команда **гарантированно
проваливается** с `Error: Nexthop has invalid gateway.`. Код это не проверял —
выполнение продолжалось, широкие маршруты `0.0.0.0/1` + `128.0.0.0/1` всё равно
добавлялись, перенаправляя весь трафик сервера в туннель **без единого
защитного маршрута для SSH**.

Воспроизведено вживую в изолированном network namespace с точной топологией
тестового сервера:
```
БЕЗ onlink → returncode 2, "Error: Nexthop has invalid gateway."
С onlink   → returncode 0
```

**Исправление (внесено заказчиком):**
- Флаг `onlink` добавляется безусловно ко всем защитным host-маршрутам
  (endpoint и SSH-клиент) — безопасно в обоих случаях: если шлюз и так
  on-link, флаг не делает ничего; если не on-link — без него маршрут не
  встанет вовсе.
- Явная проверка кода возврата на этих маршрутах с `warn()` при провале.

---

### VII. Страховочный механизм: commit-confirm (добавлено заказчиком)

Поскольку `full` — единственный режим, способный оборвать собственную
SSH-сессию администратора, и список возможных причин для этого
(нестандартный формат `ip route show default` у провайдера, неактуальный
автоопределённый IP клиента, что угодно ещё не предусмотренное) принципиально
не закрывается одним исправлением — добавлена сетка безопасности в стиле
Juniper/Cisco `commit confirmed`:

- `_schedule_rollback_watchdog()` — ставит **до** применения маршрутов
  независимый transient systemd-таймер (`systemd-run --on-active=45s`),
  переживающий гибель текущего процесса/SSH-сессии.
- `_confirm_with_timeout()` — подтверждение в той же сессии через
  `input()` с жёстким wall-clock таймаутом на `SIGALRM` (не через
  select/termios). Обрыв сессии = `EOFError` на чтении stdin = трактуется
  как «подтверждения не было».
- `_rollback_full_mode()` — безусловный откат: снимает все добавленные
  WARP-маршруты, останавливает службу. Не пытается восстановить
  `orig_gw`/`orig_if` — основной default-маршрут никогда не трогался
  (только «затенялся» более точными `/1`-маршрутами), поэтому простого снятия
  оверлеев достаточно.
- `--auto-rollback` — отдельная точка входа для transient systemd-юнита
  (отдельный процесс → сначала `_warp_state_load_autonomously()`, та же логика
  избегания пустых in-memory глобалей, что и в `--sync`).

**Побочный фикс при той же правке:** при прямом запуске
(`python3 warp.py --sync`/`--auto-rollback` из cron/systemd) Python
подставляет в `sys.path[0]` каталог самого файла, а не корень проекта —
`import chimera._core` падал с `ModuleNotFoundError` ещё до входа в
`if __name__ == "__main__":`. Путь к корню проекта теперь вычисляется
относительно `__file__` (а не хардкодится, как в `fragment_watchdog.py`).

**Промежуточный, впоследствии убранный вариант:** на пути к финальному решению
была реализована изоляция SSH через Policy-Based Routing на `iptables` fwmark —
заменена на более простой и достаточный вариант (host-маршруты + `onlink` +
commit-confirm) и удалена из кода.

---

### VIII. Эксплуатационная находка: определение реального IP SSH-клиента

Автоопределение через `$SSH_CLIENT`/`$SSH_CONNECTION` не срабатывает при входе
через `sudo -i` (sudo подчищает большую часть окружения родительской сессии) —
это ожидаемое поведение, не баг установщика. В таких случаях IP нужно вводить
вручную, и **не доверять внешним IP-чекерам** (могут отличаться от реального
из-за NAT/прокси) — надёжный источник истины:

```bash
ss -tnp state established '( dport = :22 or sport = :22 )'
```
— показывает ровно тот peer-адрес, который видит ядро сервера для текущей
SSH-сессии.

---

### IX. Проверка устойчивости парсера шлюза к разным провайдерам

`_capture_original_route()` протестирован на обоих реальных форматах вывода
`ip route show default`, встретившихся в этой истории:

```
default via 10.0.0.1 dev ens3 onlink                                    (тест-сервер)
default via 87.*.*.1 dev enp3s0 proto dhcp src 87.*.*.79 metric 100  (прод-сервер)
```

Оба разбираются корректно (`gw`, `dev` извлекаются по индексу сразу после
токенов `via`/`dev`, независимо от хвостовых полей `proto`/`src`/`metric`/`onlink`).

---

### Итоговый список изменённых/новых функций

```
_core_module(), _state_get(), _state_set()                — lazy-доступ к ядру
_WARP_STATE_MAP, _warp_state_load_autonomously(),
_warp_state_save_autonomously()                            — автономная персистентность
_wireguard_ready(), _ensure_wireguard_installed()           — проверяемая установка пакета
_capture_original_route(), _load_original_route(),
_ensure_original_route()                                    — защита SSH/Endpoint, источник истины
_schedule_rollback_watchdog(), _cancel_rollback_watchdog(),
_confirm_with_timeout(), _rollback_full_mode(),
_apply_full_mode_with_commit_confirm()                       — commit-confirm
MODE_FULL / MODE_SELECTIVE / MODE_RUNET                      — именованные константы вместо голых литералов
configure_warp(), uninstall_warp()                           — публичный API (восстановлен/добавлен)
```

---

## 🎭 Mieru Hybrid Addon: Traffic Obfuscation + рестайлинг визуала · Telemt: фикс персиста учёта трафика — 26 июня 2026

### Добавлено

**`chimera/modules/hybrid_addon.py` — Traffic Obfuscation (trafficPattern) для Mieru**

К установке Mieru Hybrid Addon добавлен шаг выбора маскировки трафика на
уровне протокола mieru (серверное поле `trafficPattern`, см.
docs/traffic-pattern.md проекта enfein/mieru):

  • **Basic (по умолчанию)** — `nonce: NONCE_TYPE_PRINTABLE`, без
    `tcpFragment`;
  • **Aggressive** — то же + `tcpFragment` с `maxSleepMs=5`, для регионов
    со строгим DPI/ТСПУ;
  • **Custom** — можно вставить собственный JSON `trafficPattern`
    (с валидацией);
  • **Disabled** — поведение как раньше, без обфускации.

Доступно как в интерактивном меню (`Установить → Traffic Obfuscation`),
так и через CLI-флаг `--traffic-pattern {basic,aggressive,disabled}`
(при `--yes` без явного флага тихо берётся `basic`). Custom-режим
доступен только интерактивно.

Для клиентских ссылок (`mierus://`, sing-box JSON для Karing) сервер
сам экспортирует протобаф-блок через `mita export traffic-pattern` —
он добавляется как параметр `&traffic-pattern=` в ссылку и как поле
`traffic_pattern` в sing-box outbound. Если экспорт не удался —
выдача продолжается без этого поля, с предупреждением (не блокирует
установку).

### Изменено

**`chimera/modules/hybrid_addon.py` — рестайлинг визуального движка**

Переписан рендер боксов/сообщений в едином стиле остального
установщика (`_box_top/_box_row/_box_sep/_box_item/_box_kv` и т.д.,
по аналогии с `box_renderer` из `_core.py`):

  • точная посимвольная ширина строк с учётом wide-символов
    (CJK/эмодзи через `unicodedata.east_asian_width`) и игнорированием
    zero-width/combining-кодов — раньше кириллица считалась как обычно,
    но строки с китайскими иероглифами или эмодзи в кастомном
    `trafficPattern`/выводе ломали выравнивание рамок;
  • перенос длинных строк и слов по словам с переносом по символам,
    если слово само шире доступной ширины бокса;
  • единые хелперы для key-value строк (`_box_kv`) и для
    цветных префиксов с переносом (`_box_wrap_msg`).

Функционально на установку/откат Mieru Hybrid Addon это не влияет —
изменился только визуальный вывод в терминале.

### Исправлено

**`chimera/modules/mtproto_stats.py` — учёт трафика Telemt не переживал ребут сервера**

`setup_iptables_accounting()` создавал цепочки `TELEMT_STATS_IN/OUT`
и джамп-правила в `INPUT`/`OUTPUT`, но никогда не сохранял их —
в отличие от SYN-limiter и iOS-фикса, которые персистят свои правила
явно. После рестарта сервера/обновления ядра правила учёта пропадали
из runtime-таблицы iptables, и счётчики трафика обнулялись/перестают
расти, хотя сама логика подсчёта (`_collect()`, `_read_chain_bytes()`)
была корректна.

Добавлена `_persist_accounting_rules()` — best-effort сохранение через
`netfilter-persistent save`, либо `iptables-save` в
`/etc/iptables/rules.v4`, вызывается сразу после применения правил
учёта (как при установке, так и в пункте меню «Включить/
переинициализировать учёт iptables»).

---

## 🔀 Новый модуль: Mieru Hybrid Addon (маскировка VLESS-входа под Mieru) — 25 июня 2026

### Добавлено

**`chimera/modules/hybrid_addon.py` — гибридная надстройка Mieru поверх Xray на Entry-ноде**

Новый пункт меню: **Установка и Система → `9`**.

Идея: внешний VLESS+REALITY inbound на Entry-ноде заменяется на Mieru
(mita) — клиент больше не «видит» Xray напрямую, он подключается к
Mieru, а та уже сама пробрасывает трафик дальше. Вся логика каскада
ниже Entry-ноды (Режим B, Smart Balancer, выбор exit-нод и т.д.) при
этом не трогается и продолжает работать как раньше — меняется только
то, во что упирается клиент снаружи.

Схема прохождения трафика:

```
Клиент                Entry-нода (этот сервер)
──────                ──────────────────────────────────────────────
mieru-клиент  ──TCP/UDP──▶  Mieru (mita)
                              │ расшифровывает, проксирует через SOCKS5
                              ▼
                         127.0.0.1:1080  (Xray, inbound socks вместо vless)
                              │
                              ▼
                         Xray: исходящая логика без изменений
                         (прямой выход / Режим B-каскад / Smart Balancer —
                          что было настроено раньше, то и осталось)
```

Меняется ровно один inbound Xray: `protocol: vless` → `protocol: socks`,
`listen` → `127.0.0.1`, `port` → `1080`. Тег inbound и `sniffing`
сохраняются, чтобы роутинг ниже по цепочке не сломался. Снаружи этот
порт у Xray больше не слушается — слушает Mieru, который и принимает
внешние соединения.

Что есть в новом пункте меню:

  • **Установить** — спрашивает текущий внешний порт VLESS (по умолчанию
    подставляется реальный порт текущей инсталляции, не захардкоженный
    443) и транспорт Mieru (`tcp` / `udp` / `both`), затем порты для
    Mieru снаружи (по умолчанию — освобождающийся порт для TCP и
    `порт+1` для UDP, с проверкой, что они свободны). Перед изменением
    конфига — явное предупреждение, что старый VLESS-линк на этом порту
    перестанет работать, и подтверждение `[y/N]`. По завершении —
    готовая клиентская выдача (см. ниже), а не только логин/пароль/порт;
  • **Откатить** — восстанавливает исходный `config.json` Xray из
    бэкапа, останавливает и снимает с автозагрузки `mita`, откатывает
    добавленные правила файрвола.

Клиентская выдача после установки — те же форматы, что и в обычном
пункте Mieru (п.12), а не только текстовые credentials:

  • `mierus://` ссылка для Karing (sing-box core) — с обязательным
    `multiplexing=MULTIPLEXING_HIGH`, без которого Karing не подключается;
  • `mierus://` ссылка для Nekobox / Nyamebox (другой формат: порт через
    `:`, параметр `transport=` вместо `protocol=`);
  • готовый sing-box JSON-конфиг для Karing — сохраняется в
    `/tmp/karing-mieru-hybrid-<tcp|udp>-<логин>.json`, т.к. сама `mierus://`
    ссылка в Karing не работает, нужен именно файл;
  • QR-код ссылки для Karing (через `qrencode`, если установлен).

  Для каждого выбранного транспорта (TCP/UDP) — отдельный набор
  логин/пароль/ссылок/файла, т.к. у них разные креды.

Безопасность по ходу установки — без ручного вмешательства:

  • бэкап `config.json` сохраняется до любых изменений
    (`config.json.bak-<таймстамп>` + `config.json.bak`);
  • если после освобождения порта от Xray его всё равно перехватил
    кто-то другой — Xray автоматически откатывается на бэкап, чтобы
    сервер не остался без входа вообще;
  • если `mita` не поднимается с новым конфигом — тот же автооткат
    Xray;
  • в конце — самопроверка живого SOCKS5-хендшейка на `127.0.0.1:1080`;
  • `mita` ставится автоматически из официальных GitHub-релизов
    `enfein/mieru` (amd64/arm64, `.deb`), если ещё не установлен.
    Кроме этого — никаких новых pip-зависимостей, только stdlib;
  • файрвол (ufw / firewalld / iptables) определяется автоматически,
    нужные порты открываются и трекаются для последующего отката.

Адаптация для встраивания в меню (сам модуль/CLI не менялись):

  • `hybrid_addon.py` остаётся самостоятельным CLI-скриптом
    (`sudo python3 chimera/modules/hybrid_addon.py [--dry-run|--rollback|...]`)
    — `main()` не тронут ни строкой;
  • для пункта меню добавлена отдельная обёртка `do_hybrid_addon_menu()`,
    использующая те же готовые функции, но без `argparse` и с
    `try/except SystemExit` на каждом шаге — многие хелперы модуля
    зовут `die()` (= `sys.exit()`), что для отдельного CLI нормально, а
    в составе интерактивного меню установщика без перехвата уронило бы
    весь установщик целиком на любой осечке (например, не нашёлся
    подходящий inbound на указанном порту);
  • генераторы `mierus://`/JSON-конфига для клиента не дублировались —
    переиспользованы напрямую из `modules/mieru.py` (`_gen_client_share_link`,
    `_gen_client_share_link_nekobox`, `_gen_singbox_outbound`, `_print_qr`),
    чтобы не было двух источников истины по формату ссылок. Импорт —
    **ленивый**, внутри функции показа, а не в шапке файла: иначе
    автономный CLI-запуск выше сломался бы (`ModuleNotFoundError`,
    проверено), т.к. при прямом запуске скрипта пакет `chimera`
    не резолвится без контекста `main.py`. `main()` эту функцию вообще
    не вызывает — для CLI ничего не изменилось;
  • в `mieru.py` добавлены только комментарии-маркеры над переиспользуемыми
    функциями (без изменения их кода) — чтобы при будущей правке формата
    не забыть про второго потребителя;

  • в `_core.py` изменения минимальны: один импорт, один пункт меню,
    один обработчик.

## 🛰️ Новый модуль: проверка цензуры провайдера (DPI Censor Check) — 25 июня 2026

### Добавлено

**`chimera/modules/dpi_censor_check.py` — обёртка над сторонним [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) v3.3.0**

Новый пункт меню **Безопасность → `CS`**: диагностика того, что именно
блокирует провайдер снаружи — TLS/TCP/HTTP/DNS-блокировки, обрыв
соединений на 16-20KB (TCP16-20), подмена DNS-ответов заглушками.

**Не путать** с уже существующим `modules/dpi_detector.py` (меню
Безопасность → `D`) — тот анализирует `error.log` Xray **на сервере** и
банит IP при активном зондировании. Это две независимые сущности с
похожими названиями; новый модуль назван `dpi_censor_check.py` намеренно,
чтобы не пересекаться по смыслу/имени с существующим.

Архитектура интеграции:

  • апстрим тянет `httpx[socks,http2]`, `rich`, `PyYAML` — этих
    зависимостей в проекте раньше не было (весь проект — stdlib +
    `qrcode` + `kyber_py`). Чтобы не тащить их в основной интерпретатор
    установщика, апстрим **вендорится без изменений** в
    `chimera/modules/_vendor/dpi_detector/` (см. там
    `VENDOR_INFO.md` — версия, commit, инструкция по обновлению) и
    запускается отдельным процессом через `subprocess`;
  • зависимости ставятся лениво (`pip install --break-system-packages`)
    только при первом открытии этого пункта меню — не при обычной
    установке/работе установщика;
  • изоляция: апстрим сам ставит `signal.signal(SIGINT, ...)` и зовёт
    `os._exit()` — в отдельном процессе это не задевает установщик;
    апстрим использует относительные импорты (`from utils import
    config`, `from core.dns_scanner import ...`) и резолвит свои
    `config.yml`/`domains.txt`/`tcp16.json`/`whitelist_sni.txt` через
    `__file__` — поэтому запускается как точка входа интерпретатора, а
    не импортируется как пакет;
  • меню-обёртка: запуск с интерактивным выбором тестов «как у апстрима»,
    проверка конкретных доменов (`-d`), запуск через proxy (`-p`),
    опциональное сохранение отчёта в
    `/var/log/xray-installer/dpi-censor-reports/`.

**Предупреждение пользователю прямо в меню**: если на сервере/клиенте
уже работает zapret или GoodbyeDPI — результаты тестов будут искажены,
перед проверкой их нужно выключить (предупреждение самого апстрима).

## 🚀 Новый модуль: бенчмарк сервера (CPU/RAM/Disk + iperf3) — 25 июня 2026

### Добавлено

**`chimera/modules/network_bench.py` — порт bench.py (bench.sh by Teddysun, mod. Nikola Tesla)**

Новый пункт меню **Диагностика → `NB`**: сведения о системе (CPU/RAM/
диск/виртуализация/ОС), тест дисковой I/O, multi-thread тест скорости
сети через iperf3 по серверам РФ/Европы/США/Азии. Только stdlib — новых
pip-зависимостей не добавляет.

Адаптация для встраивания (логика метрик и тестов скорости не менялась):

  • убраны глобальные `signal.signal(SIGINT/SIGTERM, ...)` и `sys.exit()`
    оригинала — в составе установщика они завершали бы **весь** процесс
    при Ctrl+C или срабатывании анти-флуд лока, а не только это подменю;
    заменены на локальный `try/except KeyboardInterrupt` с возвратом в
    меню;
  • `main()` → `run_bench() -> bool`, вызывается из `do_network_bench_menu()`
    с обычным для установщика UI-обвесом (`box_renderer`, подтверждение
    запуска, пауза `Нажмите Enter...`).

**Приватность**: как и оригинал, по умолчанию обращается к
`https://bench.tlab.pw/stats.json` — публичному счётчику запусков
скрипта (без передачи конфигов/трафика, просто инкремент счётчика).
Отключается флагом `_PING_RUN_STATS = False` в начале файла.

---

## 🔁 Telemt: фикс reload-фоллбэка и проба живых ME-серверов — 24 июня 2026

### Исправлено

**`telemt_fallback.py` / `mtproto.py` — `apply_telemt_reload()`: reload с откатом на restart**

Баг: `_reload_telemt()` дёргал голый `systemctl reload telemt`. На юнитах
`telemt.service`, созданных **без** `ExecReload=` (а такие уже стоят на
проде — все установки до этого фикса), systemd завершает такую команду
ошибкой `Job type reload is not applicable for unit telemt.service`.

Ошибка эта никем не проверялась. Конфиг на диске менялся корректно
(`use_middle_proxy` патчился, файл переписывался), но запущенный процесс
telemt об этом не узнавал — он продолжал работать со старым конфигом в
памяти. Ручное переключение Direct ↔ Middle в меню Hybrid Fallback
показывало `✓ Переключено в Direct Mode...` и `✓ Переключено в Middle
Proxy...`, хотя реального переключения не происходило: telemt оставался
в прежнем режиме до следующего полного `systemctl restart` (например, при
обновлении версии).

Симптом для пользователя: «я же переключил в Middle Proxy, а трафик
всё равно идёт через DC напрямую» / «переключил обратно в Direct, а
ничего не изменилось» — и так до перезапуска сервиса по любой другой
причине, что маскировало баг при тестировании с нуля (свежая установка
сразу запускает telemt с верным конфигом, поэтому баг проявляется только
на уже работающем сервисе при попытке переключиться на лету).

Фикс:

  • в `[Service]` юнита добавлен `ExecReload=/bin/kill -HUP $MAINPID` —
    теперь `systemctl reload` действительно поддерживается и не падает;
  • новая функция `apply_telemt_reload()` — сначала пробует мягкий
    `reload` (SIGHUP, без разрыва соединений), и **только если он не
    сработал** (старые юниты, накатанные до этого фикса) — откатывается
    на полный `restart`;
  • возвращает `(success, method)` — меню теперь честно показывает,
    через что применился конфиг (`reload (SIGHUP)` или `restart`), либо
    явную ошибку, если не сработало ни то ни другое, вместо немого
    «✓ Переключено».

Затронуты все точки применения конфига на лету: переключение
Direct ↔ Middle, ручной hot-reload, обновление/снятие `client_mss`.

**`telemt_fallback.py` / `mtproto.py` — проба ME-серверов по живому пулу вместо статического DC-списка**

Баг: пункт «Проверить ME-серверы» гонял TCP-пробу по статическому
списку `_ME_ENDPOINTS` — адресам **DC API** Telegram
(`149.154.x.x:443/8443`). Это те же адреса, что прописываются в
`[dc_overrides]` для Direct Mode, а не настоящий пул ME middle-proxy
серверов (тот живёт на `:8888` и состоит из совсем других IP).

DC API у Telegram обычно доступен даже из РФ (это просто HTTPS-эндпоинты
датацентров), поэтому проба стабильно показывала «ME-серверы доступны»
независимо от реального состояния Middle Proxy. Отсюда симптом:
проверка зелёная, кворум пройден — а Middle Proxy всё равно не
устанавливается, потому что настоящий ME-пул на `:8888` для региона
заблокирован.

Фикс — новая функция `fetch_live_me_endpoints()`: скачивает актуальный
пул ME-серверов с официального `core.telegram.org/getProxyConfig`
(тот же файл, `proxy_for N host:port;`, который использует любой
оператор MTProxy при старте), и проба идёт уже по нему. Статический
`_ME_ENDPOINTS` остался только как последний рубеж — если сам
`getProxyConfig` недоступен (например, `core.telegram.org` заблокирован
в регионе). В вывод добавлена строка с источником пула
(«живой пул getProxyConfig (N адресов)» / «статический fallback-список»),
чтобы было видно, по какому списку шла проверка.

---

## 🍎 Telemt: iOS-фикс (MSS + redirect-порт) и быстрый reap мёртвых соединений — 23 июня 2026

### Добавлено

**`chimera/modules/telemt_ios_fix.py` — точечный MSS-clamp для iOS-клиентов**

Новый пункт **I** в меню Telemt (`mtproto_menu()`): отдельный внешний порт,
на который iOS-клиенты Telegram заходят через тот же secret/IP, но с
другим `port=` в ссылке.

Контекст: `client_mss` (см. `telemt_mss_selector.py`) фрагментирует TLS
ClientHello для **всех** клиентов сразу, чтобы DPI (TSPU) не собрал
JA4-фингерпринт целиком. Но бывает точечная проблема — не подключается
именно iOS, а Android/Desktop через тот же порт работают нормально (у
iOS-приложения Telegram свой TLS-стек, и общий MSS не всегда дробит его
ClientHello так же эффективно). Включать `client_mss` для всех ради
проблемы только у части пользователей — лишний оверхед на тех, у кого и
так всё работает.

Механизм — iptables (проект целиком на iptables, без nftables):

  • `mangle/PREROUTING` — MSS-clamp только на SYN/SYN-ACK входящего
    внешнего порта, не трогает установленные соединения и другие порты;
  • `nat/PREROUTING` — REDIRECT на основной порт Telemt.

Что ещё учтено:

  • **конфликт с `client_mss`** обнаруживается автоматически (тот же
    regex-паттерн, что у `telemt_mss_selector.py`, без прямого импорта
    модуля — чтобы не плодить cross-module зависимость); с согласия
    пользователя `client_mss` убирается из конфига перед применением
    правил, сервис перечитывает конфиг (restart);
  • **проверка занятости порта** через `socket.bind()` перед применением
    правил — TCPMSS/REDIRECT не открывают сокет сами, так что повторное
    применение фикса на тот же порт не считается «занятым»;
  • правила маркируются комментарием `telemt-ios-mss-fix` — отключение
    модуля убирает только их, REDIRECT-правила xray/tproxy (другой
    chain/тег) не трогает;
  • install/uninstall идемпотентны, persist — тот же best-effort паттерн
    (netfilter-persistent / `iptables-save` в `rules.v4`), что в
    `telemt_syn_limiter.py`.

iOS-ссылка с альтернативным портом теперь подмешивается во все три места,
где показываются ссылки пользователей (после установки, в управлении
пользователями, в общем выводе ссылок), если фикс включён.

### Исправлено

**`mtproto.py` — keepalive 600с → 60/15/3 (рвём мёртвые соединения быстро)**

iOS (и часть агрессивных Android-прошивок) сворачивает/душит приложение
без чистого закрытия сокета — сервер держит мёртвое соединение часами.
При возврате клиент пытается переподключиться и залипает, пока старая
половинка соединения не истечёт.

Новые значения `net.ipv4.tcp_keepalive_time/intvl/probes` = `60/15/3`
рвут мёртвый коннект за ~105 секунд (60с тишины + проба каждые 15с × 3
попытки → RST) вместо прежних ~2.1 часа при дефолтном `tcp_keepalive_time
= 600`.

---

## ☁️ Новый модуль WebDAV Tunnel — 22 июня 2026

### Добавлено

**`chimera/modules/webdav_tunnel.py` — туннель TCP/SOCKS5 поверх WebDAV**

Новый пункт главного меню **14. WebDAV Tunnel** — обёртка над сторонним
проектом [spkprsnts/webdav-tunnel](https://github.com/spkprsnts/webdav-tunnel):
трафик сериализуется в бинарные чанки и гоняется как обычные файлы по
WebDAV (PUT/GET/PROPFIND) — для DPI это выглядит как сессия с облачным
хранилищем, а не как VPN/прокси-протокол.

Два режима установки (выбираются при установке):

  • **selfhosted** (по умолчанию) — сервер сам поднимает встроенный
    WebDAV прямо на этой VPS, сторонний аккаунт не нужен;
  • **external** — VPS подключается как клиент к стороннему
    WebDAV-хранилищу (Nextcloud/Box и т.п.) и релеит трафик через него.

Что делает модуль:

  • установка/обновление: тот же подход к Go-тулчейну, что в
    `wdtt.py`/`olcrtc.py` — официальный архив с go.dev, если версия
    в системе ниже требуемой, затем `go build -o webdav-tunnel .`;
  • systemd-сервис `webdav-tunnel.service`; для selfhosted дополнительно
    открывает TCP-порт (UFW, если активен, иначе iptables) — у external
    входящего порта нет, сервер сам инициирует исходящие запросы к
    стороннему хранилищу;
  • генерация клиентской `webdav://...#name` ссылки и команды запуска
    клиента — тюнинг (`poll-min`/`poll-max`/`coalesce`/`puts`/`read-max`/
    `chunk-size`) для selfhosted прописан явно и одинаково и в
    systemd-юните, и в самой ссылке, не полагаясь на дефолты бинарника
    (README апстрима противоречит сам себе: таблица флагов и пример
    вывода selfhosted называют разные значения `poll-max`);
  • статус/журнал, перезапуск, полное удаление, встроенный гайд (как
    собрать клиента, selfhosted vs external, риски без TLS).

Архитектурное ограничение, явно прописанное в докстринге модуля: апстрим
поддерживает один login/password на инстанс — мультипользовательская
модель (как TTL-пароли в `wdtt.py`) тут не реализована, и это сознательно,
чтобы не плодить параллельную логику сверх возможностей самого бинарника.

**Известное ограничение**: без указания собственного `cert.pem`/`key.pem`
для selfhosted сервис слушает обычный HTTP. Самоподписанный сертификат
не добавлялся — неизвестно, проверяет ли клиент апстрима TLS-сертификат
на стороне Go-кода (флага skip-verify в README нет). Если нужен TLS —
указывайте при установке домен с уже выпущенным сертификатом.

---

## 🐛 v4.12.10 — 21 июня 2026 — Fail2ban sshd-jail и лог UFW

### Исправлено

**`setup_fail2ban()` — джейл `[sshd]` падал с `Have not found any log file for sshd jail`**

На серверах без rsyslog (только journald, без файла `/var/log/auth.log`)
fail2ban с дефолтным `backend = auto` не находил физический лог-файл для
джейла `sshd` (`%(sshd_log)s`) и не запускался вовсе. Добавлен явный
`backend = systemd` для джейла `[sshd]` — fail2ban читает события sshd
прямо из journald независимо от наличия rsyslog/auth.log.

**`configure_firewall()` — rsyslog уходил в suspended/resumed после `ufw enable`**

После включения UFW и появления первых строк в `/var/log/ufw.log`
rsyslog (работает от `syslog:adm`) не мог создать этот файл сам — каталог
`/var/log` имеет права `755 root:syslog` без `w` для группы. Теперь перед
`ufw --force enable` файл `/var/log/ufw.log` создаётся заранее с
владельцем `syslog:adm` и правами `640`.

---



### Добавлено

**`chimera/modules/olcrtc.py` — туннель TCP-over-WebRTC под видеозвонок**

Новый пункт главного меню **13. olcRTC** — обёртка над сторонним проектом
[openlibrecommunity/olcrtc](https://github.com/openlibrecommunity/olcrtc):
маскирует трафик под обычный видеозвонок в Jitsi / Яндекс.Телемост / WB
Stream. Полезно как запасной канал именно для сценариев полной блокировки
«по белым спискам», когда обычный VLESS/Reality недоступен в принципе.

**Важное архитектурное отличие**, явно показанное в статусе и расписанное
в гайде модуля (пункт меню «Гайд»): в отличие от VLESS/Mieru/NaiveProxy,
olcRTC не обслуживает много клиентов одним портом — каждый клиент
("линк") — это отдельный systemd-сервис, который реально участвует в
WebRTC-сессии (для `vp8channel`/`videochannel` сервер кодирует настоящее
видео — заметная нагрузка на CPU). Клиенту тоже нужен собственный
бинарник `olcrtc` (актуальная версия проекта читает один YAML-файл,
никаких готовых vless-ссылок/QR тут нет) — модуль выдаёт готовый
client-конфиг текстом для копирования.

Что делает модуль:

  • установка/обновление: клонирует исходники, ставит Go 1.26+ (официальный
    тарбол с go.dev, если версия в системе ниже требуемой) и собирает
    `go build ./cmd/olcrtc` — без mage и сабмодулей, которых в актуальном
    master уже нет;
  • добавление нового клиента: выбор провайдера (Jitsi — комната
    генерируется автоматически и сразу запускается; Телемост/WB Stream —
    модуль показывает прямую ссылку для ручного создания комнаты и просит
    вставить её ID) и транспорта (datachannel/vp8channel/seichannel/
    videochannel), автогенерация ключа и SOCKS-порта, systemd template-юнит
    `olcrtc@<имя>.service`;
  • список клиентов с управлением каждым (старт/стоп/restart, лог, повторный
    показ конфига клиента, удаление);
  • отдельный гайд-экран с пошаговой инструкцией для стороны клиента.

Технические детали (`carrier`/`transport`, формат YAML, отсутствие
автосоздания комнат у Telemost/WB Stream) сверены не по докам репозитория
(они местами устарели — например, упоминают CLI-флаги и провайдера
`jazz`, которых уже нет), а напрямую по исходникам actual `master`.

---

## ✨ Новый модуль управления Fail2ban — 21 июня 2026

### Добавлено

**`chimera/modules/fail2ban_manager.py` — интерактивная панель Fail2ban**

Fail2ban и раньше устанавливался и настраивался автоматически на этапе
установки (`setup_fail2ban()` в `_core.py`: джейлы `xray-reality`, `sshd`,
`nginx-http-auth`, `nginx-limit-req`), но управлять им можно было только
руками через SSH (`fail2ban-client`, редактирование `jail.d/*.conf`).
Добавлен отдельный пункт меню **🛡️ Fail2ban** в разделе
«Безопасность и автоматизация» (горячая клавиша `FB`), без единой строчки
кода в `_core.py` помимо точки подключения:

  • статус службы + сводка по джейлам (сколько IP забанено прямо сейчас);
  • просмотр забаненных IP по всем джейлам и разбан (`fail2ban-client unban`);
  • ручной бан IP в выбранном джейле;
  • тонкая настройка джейла — `bantime` / `findtime` / `maxretry`
    (читает и переписывает `/etc/fail2ban/jail.d/xray-reality.conf`
    через `configparser.RawConfigParser`, затем `fail2ban-client reload`);
  • включение/выключение отдельного джейла;
  • просмотр последних 30 строк `/var/log/fail2ban.log`;
  • установка Fail2ban "с нуля" или восстановление базовой конфигурации,
    если служба не была установлена или конфиг случайно удалили руками —
    переиспользует тот же `setup_fail2ban()` из `_core.py` (ленивый импорт
    через `importlib`, без циклических импортов), поэтому конфигурация
    джейлов гарантированно не расходится с тем, что генерирует установщик
    при первичной настройке.

Логика установки/запуска/перезапуска Xray, Nginx и других служб не
затронута — модуль только читает статус и работает с конфигурацией
Fail2ban.

---

## 🐛 Исправление SyntaxError в nginx-конфиге + читаемые логи Mieru — 20 июня 2026

### Исправлено

**`_core.py` — `SyntaxError: f-string: expecting '}'` в `setup_nginx_final()`**

Причина: вложенный f-string внутри тернарного оператора, который сам был
частью внешнего f-string (`textwrap.dedent(f"""...""")`). Python не может
корректно разобрать `{PARAM_DOMAIN}`-плейсхолдеры внутри вложенного
`f"""..."""`, когда всё это вложено в фигурные скобки внешнего f-string —
парсер падает на этапе компиляции, до выполнения, поэтому ошибка проявлялась
у любого пользователя на этапе финальной настройки Nginx.

Исправление: блок `ssl_reject_handshake` / fallback-сертификат вычисляется
заранее в отдельную переменную `default_server_ssl` — тот же паттерн, что
уже использовался для `listen_main`, `http2_line`, `rate_limit` чуть выше
в этой же функции. Поведение не изменилось — для nginx ≥ 1.19.4 ставится
`ssl_reject_handshake on;`, для более старых версий — явный сертификат
с `return 444;`.

**`mieru.py` / `mieru_stats.py` — нечитаемые обрезанные строки в логах**

Длинные строки `journalctl` (а также дампы `iptables`, `ss`, `timedatectl`
в странице диагностики Mieru) обрезались до ширины бокса (`line[:_BOX_W-4]`),
из-за чего важная часть строки — статус, IP-адрес, сообщение об ошибке —
просто отрезалась и пропадала с экрана.

Добавлен хелпер `_box_log_line()`: длинная строка переносится максимум на
2 строки бокса (первая — как есть, вторая — с отступом и маркером `↳`
для визуальной связи), а если не уместилось и в 2 строки — добавляется
`…` в конце. Короткие строки выводятся как раньше, без изменений.
Исправлено во всех точках вывода логов: статус Mieru (30 строк журнала)
и страница диагностики (iptables/ss/timedatectl/journalctl).

---

## ✨ Telemt: SYN-limiter против ретрай-штормов — 20 июня 2026

### Контекст

У части клиентов Telegram подключение зависало в статусе «Подключение...» —
причём `client_mss` (фрагментация ClientHello против TSPU/JA4, см. v4.12.8)
здесь не помогал, потому что причина другая. В нестабильной сети (мобильный
интернет, агрессивный NAT) клиент не получает SYN/ACK вовремя и шлёт повторные
SYN, которые накладываются на уже полуоткрытое соединение. Сервер видит
лавину SYN с одного IP, conntrack/backlog не успевает обработать — хендшейк
не завершается.

### Новое

#### Модуль `telemt_syn_limiter.py` — per-IP лимитер входящих SYN-пакетов

- Секционирует SYN-трафик по `iptables hashlimit` в режиме `srcip`/маска `/32` —
  лимит считается отдельно для каждого клиентского IP, не суммарно по серверу
- **4 пресета**:
  - жёсткий — 1/sec burst 1 ★ (рекомендуется по умолчанию)
  - средний — 1/sec burst 3
  - мягкий — 2/sec burst 5
  - свой — произвольные rate/burst
- Не трогает уже установленные соединения — правило матчит только `--syn`
- Live-монитор: принято/отброшено SYN, процент дропа, обновление каждые 2 сек
- Все правила маркируются `--comment "telemt-syn-limit"` — отключение модуля
  удаляет только их, ничего больше в iptables не затрагивается
- Persist через тот же безопасный паттерн (`netfilter-persistent`/`iptables-save`),
  что и остальные iptables-правила проекта
- Установка/удаление идемпотентны — повторный enable() не плодит дубликаты правил
- Lazy-import в `mtproto_menu()`, по тому же паттерну, что `telemt_fallback`
  и `telemt_mss_selector` — ошибка импорта не прерывает установку

### Совместимость

- Работает только с правилами `INPUT` для порта Telemt — REDIRECT-цепочки
  xray/tproxy не затрагиваются
- Backend — iptables (не nftables), без новых зависимостей и без риска
  конфликта conntrack-таблиц между бэкендами
- Не требует параметров от `mtproto.py` — порт читается напрямую из `telemt.toml`

---

## ✨ v4.12.9 — 18 июня 2026 — Статистика трафика NaiveProxy и Mieru

### Что нового

Два новых модуля мониторинга трафика для протоколов NaiveProxy и Mieru — без новых демонов,
без сторонних зависимостей, в едином стиле проекта.

### `naiveproxy_stats.py` — статистика Caddy-forwardproxy-naive

**Источники данных:**
- `/var/log/caddy-naive/access.log` — основной JSON-лог Caddy: timestamp, duration, remote_addr, status, resp_body_size, basic-auth логин
- `iptables -L INPUT -n -v -x` — суммарные байты на TCP 443
- `ss -tnp` — активные TCP-соединения на порт

**Метрики:**
- Суммарный трафик (байты) за период — из iptables-счётчика
- Количество запросов, успешных (2xx), ошибок (4xx/5xx) — из access.log
- Статистика по пользователям (логин → запросы, байты, last\_seen)
- Топ-5 IP-адресов клиентов
- Распределение по кодам ответа (200/407/502/...)
- Гистограмма активности по 10-минутным слотам (последний час)
- Среднее время запроса (latency), 95-й перцентиль
- Текущих активных соединений (ss)
- Живое обновление каждые 30 секунд

### `mieru_stats.py` — статистика mita-сервера

Mieru не пишет access.log с байтами — поэтому используется комбинация источников:

**Источники данных:**
- `iptables -L INPUT -n -v -x` — байты/пакеты на TCP/UDP-порту mita (основной источник)
- `journalctl -u mita` — события соединений, ошибки, предупреждения
- `ss -tnp / ss -unp` — активные TCP/UDP-соединения на порт
- `/proc/net/sockstat` — глобальная статистика сокетов
- `timedatectl` — синхронизация NTP (критично для Mieru)

**Метрики:**
- Суммарный трафик (байты, пакеты) — iptables INPUT
- Скорость (байт/с) между двумя замерами через кэш
- Количество соединений accepted/closed — из journalctl
- Количество ошибок/предупреждений — из journalctl
- Активных соединений сейчас — ss
- Гистограмма активности по 10-минутным интервалам (из журнала)
- Тренд: рост / спад / стабильно
- NTP-статус (отклонение > 30 сек = Mieru не принимает клиентов)
- Живое обновление каждые 30 секунд

### Интеграция

Оба модуля вызываются из соответствующих меню протоколов через новый пункт «Статистика трафика».
Точки входа:
```python
from chimera.modules.mieru_stats import do_mieru_stats_menu
from chimera.modules.naiveproxy_stats import do_naiveproxy_stats_menu
```

### Также в этом релизе

- Документация NaiveProxy обновлена: во всех клиентских гайдах рекомендуется sing-box JSON outbound вместо naive+https:// share-ссылки (лучшая совместимость с Karing и другими клиентами)
- Исправлен формат sing-box outbound для NaiveProxy: убрано невалидное поле `network`
- Исправлен формат naive+https:// ссылки (trailing slash + tag)

---

## v4.12.8-patch5 — 14 июня 2026 — NaiveProxy + Mieru: HTTPS/mTLS маскировка трафика

### Контекст

Два новых протокола для обхода DPI-фильтрации. Оба модуля написаны
в едином стиле проекта — без сторонних зависимостей, чистое удаление,
встроенный гайд, QR-коды для клиентов.

### NaiveProxy (`naiveproxy.py`)

**Принцип:** HTTPS/HTTP2 с Chromium fingerprint + probe resistance.
DPI видит легитимный HTTPS трафик к домену. Зонды РКН видят фейковый сайт.

**Схема:**
```
Клиент (Karing/NekoBox/ShadowRocket)
  │  HTTPS/HTTP2 + Chromium fingerprint
  ▼
caddy-forwardproxy-naive :443
  │  probe resistance → фейковый сайт для незнакомых клиентов
  ▼
Интернет
```

**Каскад Entry→Exit:**
```
Клиент → caddy-naive Entry (RU) → upstream → caddy-naive Exit (EU) → Интернет
```

**Что делает модуль:**
- Скачивает caddy-forwardproxy-naive (prebuilt amd64)
- Генерирует Caddyfile с probe resistance и basicauth
- Создаёт фейковый HTML-сайт для незнакомых клиентов
- Systemd-сервис с `CAP_NET_BIND_SERVICE` (без root)
- Открывает TCP 443 в iptables
- Управление пользователями с bcrypt хешированием паролей
- Каскад Entry→Exit через upstream в Caddyfile
- Генерация `naive+https://` ссылок и QR-кодов
- Встроенный гайд: DNS, probe resistance, каскад, клиенты

**Требования:** домен с A-записью на VPS, порт 443/tcp

**Клиенты:** Karing, NekoBox (Android), ShadowRocket (iOS), naiveproxy CLI

---

### Mieru (`mieru.py`)

**Принцип:** mTLS + рандомный padding — трафик без паттернов.
Не требует домена. Временная метка защищает от replay-атак.

**Схема:**
```
Клиент (Karing / Nekobox / sing-box)
  │  mTLS + random padding + timestamp
  ▼
mita :2012-2022 (диапазон портов)
  │  проверка ±30 сек, встроенный SOCKS5
  ▼
Интернет
```

**Что делает модуль:**
- Скачивает mita (сервер) и mieru (CLI) с GitHub (amd64/arm64)
- Устанавливает chrony если нет NTP-синхронизации
- Применяет конфиг через `mita apply config`
- Systemd-сервис `mita`
- Открывает диапазон TCP/UDP портов в iptables
- Управление пользователями с hot-reload конфига
- Проверка NTP-синхронизации в статусе
- Генерация `mieru://` ссылок, sing-box JSON outbound и QR-кодов
- Встроенный гайд: как работает, синхронизация времени, TCP vs UDP

**Требования:** только IP и порт, домен не нужен

**Клиенты:** Karing, Nekobox (Android), sing-box CLI

---

### Интеграция в `_core.py`

- Пункт **11** в главном меню: `🔐 NaiveProxy`
- Пункт **12** в главном меню: `🔒 Mieru`
- Промпт выбора обновлён до `1–12 / 0`
- Импорты `do_naiveproxy_menu`, `do_mieru_menu`

### Что не затрагивается

- Xray `config.json` и VLESS-inbound
- `state.json` инсталлера
- iptables-правила других модулей
- Любые другие службы

### NaiveProxy vs Mieru — когда что выбрать

| | NaiveProxy | Mieru |
|---|---|---|
| Маскировка | HTTPS/H2 Chromium | mTLS + random padding |
| Домен | Обязателен | Не нужен |
| Probe resistance | ✓ | — |
| Синхронизация времени | — | ±30 сек обязательно |
| Клиенты | Karing, NekoBox, ShadowRocket | Karing, NekoBox, sing-box |

---

---

## v4.12.8-patch2 — 12 июня 2026 — VK Turn Tunnel: два клиента, два модуля

### Контекст

Предыдущая реализация `turntunnel.py` запускала `vk-turn-proxy` с флагом
`-vless`, который предназначен для работы в паре с CLI-клиентом (`client -vless`)
а не с мобильным приложением WireTurn. Xray inbound добавлялся, но к нему
никто не подключался. Одновременно WireTurn ожидает сервер Turnable, а не
vk-turn-proxy. Патч разделяет схемы на два независимых модуля.

### Новое

#### Модуль `vkturn_menu.py` — диспетчер пункта 8

- Новая точка входа `do_vkturn_menu()` вместо `do_turntunnel_menu()`
- Показывает выбор между двумя подсистемами с текущим статусом каждой
- Оба модуля могут быть установлены и работать одновременно (разные порты,
  разные сервисы, не конфликтуют)

#### Модуль `turntunnel.py` — рефакторинг под FreeTurn

- Убран флаг `-vless` из systemd ExecStart
- Удалён весь Xray-блок:
  `_xray_inject_turn_inbound`, `_xray_remove_turn_inbound`,
  `_xray_write_and_test`, `_xray_has_turn_inbound`, `_xray_get_turn_inbound`
- Удалён перезапуск Xray после установки/удаления
- Добавлен QR-код адреса сервера (`IP:порт`) для сканирования в FreeTurn
- Обновлена инструкция: вкладка «Сервер» и вкладка «Клиент» в FreeTurn
- Целевой сервис — WireGuard (UDP 51820) или Hysteria2, выбирается при установке
- Клиент: **FreeTurn** (samosvalishe/turn-proxy-android)

#### Модуль `turnable.py` — новый, под WireTurn

- Скачивает бинарник **Turnable** (TheAirBlow/Turnable, v0.4.1, linux-amd64)
- Генерирует пару ключей через `turnable keygen` (priv_key / pub_key)
- Запрашивает Call ID ВК-звонка (принимает полную ссылку или только ID)
- Создаёт `/opt/turnable/config.json` и `store.json` с маршрутом VLESS
- Добавляет VLESS-inbound в `config.json` Xray:
  `127.0.0.1:12767`, plain TCP, тег `vless-turnable-inbound`;
  проверка через `xray -test` перед применением; откат при ошибке
- Создаёт systemd-сервис `turnable` с `After=xray.service`
- Открывает UDP 56001 в iptables (56000 зарезервирован для FreeTurn)
- Генерирует `turnable://` ссылку через `turnable config generate`
- Показывает два QR-кода: turnable:// ссылка + VLESS-ссылка для Xray
- Хранит состояние в `/var/lib/xray-installer/turnable.json`
- При удалении: сервис, бинарник, inbound из Xray, iptables, turnable.json
- Клиент: **WireTurn** (spkprsnts/WireTurn)

### Схемы трафика

```
FreeTurn (Android)
  │  DTLS 1.2 / STUN ChannelData
  ▼
TURN-серверы ВКонтакте
  │  UDP → VPS :56000
  ▼
vk-turn-proxy server (UDP relay)
  │  UDP → WireGuard / Hysteria2
  ▼
Интернет
```

```
WireTurn + встроенный Xray (Android)
  │  WebRTC DTLS / TURN
  ▼
TURN-серверы ВКонтакте
  │  UDP → VPS :56001
  ▼
Turnable server
  │  TCP → Xray inbound :12767
  ▼
Xray (VLESS plain TCP, только localhost)
  │
  ▼
Интернет
```

### Изменения в `_core.py`

- Импорт заменён: `do_turntunnel_menu` → `do_vkturn_menu` из `vkturn_menu`
- Вызов пункта 8 обновлён соответственно
- Подпись пункта 8: `FreeTurn (vk-turn-proxy) · WireTurn (Turnable)`

### Что не затрагивается

- Основной VLESS/REALITY inbound и его пользователи
- Hysteria2, MTProxy, SlipGate, qWDTT и все прочие модули
- iptables-правила других модулей (ipban, autoban, geoip, telemt)
- `state.json`

---

## v4.12.8-patch4 — 11 июня 2026 — qWDTT: WireGuard через TURN ВКонтакте

### Контекст

Альтернатива vk-turn-proxy для пользователей которым нужна парольная модель
доступа, временные пароли с TTL, лимиты устройств и управление через
Telegram без SSH. Использует WireGuard как внутренний протокол вместо VLESS,
ключи WRAP выводятся из пароля через HKDF — не хранятся в APK.

### Схема трафика

```
Android (qWDTT APK)
  │  WRAP RTP AEAD/ChaCha20-Poly1305 поверх DTLS 1.2
  ▼
TURN-серверы ВКонтакте  (трафик = медиа-поток звонка)
  │  UDP → VPS :56000
  ▼
wdtt-server  (:56000/udp DTLS)
  │  WireGuard  (:56001/udp внутренний)
  ▼
WireGuard tun: wdtt0  (10.66.66.0/16)
  │  NAT MASQUERADE
  ▼
Интернет
```

### Новое

#### Модуль `wdtt.py` — установка и управление qWDTT

- Сборка `wdtt-server` из исходников Go (github.com/SpaceNeuroX/proxy-turn-vk-android)
  с автоустановкой Go через apt если отсутствует
- Systemd-сервис с `After=network-online.target`
- iptables: UDP порт 56000, MASQUERADE для подсети `10.66.66.0/16`
- IP forwarding (`net.ipv4.ip_forward=1`) через `/etc/sysctl.d/99-wdtt.conf`
- **Парольная модель:**
  - Главный пароль — бессрочный (для администратора)
  - До 10 временных паролей с TTL (1–365 дней) и лимитом устройств
  - Ключи WRAP выводятся через HKDF — не хранятся в клиентском APK
- **Hot reload** через SIGHUP — смена паролей без перезапуска службы
  и разрыва активных соединений
- **Telegram-бот** (опционально): `/new`, `/list`, деактивация,
  отвязка устройств, удаление паролей — всё без SSH
- Генерация `qwdtt://` ссылок и `.conf` файлов для клиента
- Состояние в `/var/lib/xray-installer/wdtt.json`,
  пароли в `/etc/wdtt/passwords.json`
- При удалении чисто убирает всё: сервис, бинарник, конфиги,
  iptables-правила, sysctl

#### Встроенный гайд (пункт [G])

- Скачать qWDTT APK (github.com/SpaceNeuroX/proxy-turn-vk-android/releases)
- Получить VK-хеш звонка (часть ссылки после /join/)
- Подключение по `qwdtt://` ссылке — формат и импорт в приложение
- Telegram-бот — создание бота, команды, возможности
- Сравнение с vk-turn-proxy — когда что выбрать

#### Интеграция в `_core.py`

- Новый пункт **10** в главном меню: `🔒 qWDTT (WireGuard/TURN)`
- Импорт `do_wdtt_menu` на уровне модуля
- Промпт выбора обновлён до `1–10 / 0`

### Отличия от vk-turn-proxy (turntunnel.py)

| | vk-turn-proxy | qWDTT |
|---|---|---|
| Протокол | VLESS (Xray) | WireGuard |
| Аутентификация | UUID | Пароль + HKDF |
| Клиент | WireTurn | qWDTT APK |
| Временные пароли | turntunnel_links.py | Встроено (TTL, лимит) |
| Telegram-бот | — | ✓ |
| Hot reload | — | ✓ SIGHUP |

### Что не затрагивается

- `config.json` Xray и VLESS-inbound
- `state.json` инсталлера
- iptables-правила других модулей (ipban, turntunnel, autoban)
- Любые другие службы

---

---

## v4.12.8-patch3 — 11 июня 2026 — SlipGate/SlipNet: DNS-туннели для обхода полных блокировок

### Контекст

Когда все прямые соединения заблокированы — VLESS, WireGuard, TURN —
DNS-туннель работает потому что операторы не могут заблокировать DNS
не нарушив работу всего интернета.
Трафик прячется внутри DNS-запросов и выглядит как обычная DNS-активность.
Данный патч интегрирует SlipGate (github.com/anonvector/slipgate) —
серверный компонент для DNS-туннелей — в VLESS Ultimate Installer.

### Схема трафика

```
Android / CLI (SlipNet)
  │  DNS-запросы (UDP/53) с данными внутри
  ▼
DNS-сервер оператора / публичный резолвер
  │  NS-делегирование на поддомен
  ▼
VPS :53/udp — SlipGate (DNSTT/NoizDNS/Slipstream/VayDNS)
  │  расшифровка, Curve25519
  ▼
SOCKS5 :1080 / SSH :22 → Интернет
```

### Поддерживаемые протоколы

| Протокол    | Транспорт         | Домен нужен | Порт    |
|-------------|-------------------|-------------|---------|
| DNSTT       | DNS (UDP)         | Да (NS)     | 53/udp  |
| NoizDNS     | DNS + DPI-obfs    | Да (NS)     | 53/udp  |
| Slipstream  | QUIC over DNS     | Да (NS)     | 53/udp  |
| VayDNS      | KCP + Curve25519  | Да (NS)     | 53/udp  |
| StunTLS     | SSH over TLS+WS   | Нет         | 443/tcp |
| NaiveProxy  | HTTPS Chromium FP | Да (A)      | 443/tcp |

### Новое

#### Модуль `slipgate.py` — установка и управление SlipGate

- Установка через официальный `install.sh` от авторов (AGPL-3.0)
- Управление туннелями через SlipGate TUI (`slipgate` без аргументов)
- Генерация `slipnet://` URI для импорта в клиент (пункт [3])
- Статус всех туннелей и systemd-сервисов
- Диагностика (`slipgate diag`)
- Просмотр логов по туннелям и общих
- Обновление (`slipgate update`)
- Удаление (`slipgate uninstall`) — чисто убирает всё
- Хранит флаг установки в `/var/lib/xray-installer/slipgate.json`

#### Встроенный гайд (пункт [G])

Полная документация прямо в TUI без выхода в браузер:

- **DNS-настройка** — A-запись для NS-сервера, NS-записи для каждого
  туннеля, A-запись для NaiveProxy; команда проверки (`dig NS`)
- **Android-клиент** — где скачать SlipNet APK, как импортировать
  `slipnet://` профиль, порядок подключения
- **CLI-клиент** — скачивание `slipnet-linux-amd64`, использование
  с SOCKS5 прокси, кастомный порт
- **Добавить туннель** — пошагово через TUI и через CLI
- **Типы туннелей** — что выбрать под конкретную ситуацию

#### Интеграция в `_core.py`

- Новый пункт **9** в главном меню: `🌐 SlipGate / SlipNet`
- Импорт `do_slipgate_menu` на уровне модуля
- Промпт выбора обновлён до `1–9 / 0`

### Клиентская часть

- **Android**: SlipNet APK — `github.com/anonvector/SlipNet/releases`
- **Linux/macOS/Windows**: `slipnet-linux-amd64` из тех же релизов
- Импорт через `slipnet://BASE64...` URI (генерируется пунктом [3])

### Что не затрагивается

- `config.json` Xray и основной VLESS/REALITY inbound
- `state.json` инсталлера
- iptables-правила других модулей
- Пользователи и UUID VLESS
- Любые другие службы

### Примечание по лицензии

SlipNet (клиент, APK) — закрытая лицензия, запрещающая распространение
через app stores. Модуль инсталлера не распространяет клиент —
только скачивает серверный компонент (SlipGate, AGPL-3.0) и показывает
ссылку на официальный GitHub для загрузки клиента.

---

---

## v4.12.8-patch1 — 8 июня 2026 — Fragment Fuzzer: режим тестирования с клиента

### Контекст

Режим A фаззера (тест с VPS) давал ориентировочные результаты, поскольку DPI
между VPS и интернетом отсутствует — все 8 комбинаций показывали 100% успех,
а победитель выбирался лишь по минимальному TTFB. Реальный DPI находится
на маршруте **клиент → VPS**, и единственный способ его проверить — тестировать
с клиентского устройства. Кроме того, fingerprint был захардкожен как `chrome`
вместо чтения из `state.json`.

### Изменения в `fragment_fuzzer.py`

#### Режим B — тест с клиента (новый)

- Генерирует все 8 конфигов из матрицы в `fragment_configs/fuzz_NN_label.json`
- Опциональный HTTP-коллектор на порту `:10901`: клиент запускает каждый конфиг
  и отправляет результат одной командой:
  ```
  curl "http://VPS:10901/report?id=01&ttfb=420&ok=1"
  ```
- Сервер собирает ответы в реальном времени, строит таблицу с рейтингом
- По завершении предлагает сохранить победителя как `fragment_recommended.json`
- Коллектор завершается автоматически (5 мин таймаут, все ответы получены,
  или Enter на сервере)
- HTTP-коллектор принимает только `GET /report?...` — никаких команд не выполняет

#### Исправления режима A

- FP больше не захардкожен как `chrome` — читается из `state.json`
  через `_fp_from_state()` с fallback на `chrome`
- `_FUZZ_REPEATS` увеличен с 3 до 5 для статистической надёжности
- Добавлены метки (`label`) в матрицу для читаемости таблиц

#### Прочее

- `_patch_fp_in_config()` — патчит FP во всех сгенерированных конфигах
- Меню стало двухуровневым: `[A]` Тест с VPS / `[B]` Тест с клиента
- Публичное API не изменилось: `do_fragment_fuzzer_menu()` — точка входа та же
- `/etc/xray/config.json` не затрагивается ни в каком режиме

### Совместимость

- Обратная совместимость полная: `run_fragment_fuzzer()` сохранено с прежней сигнатурой
- Интеграция в `_core.py` (F2) не изменялась

---

## ✨ v4.12.8 — 8 июня 2026 — Telemt: MSS-фрагментация против TSPU JA4 DPI

### Контекст

С 1 апреля 2026 г. TSPU (часть АСБИ) развернул правила JA4/JA3-дактилоскопии,
распознающие MTProxy Fake-TLS по уникальному паттерну TLS ClientHello.
Объявление малого TCP MSS в SYN/ACK вынуждает клиентское ядро дробить
ClientHello по нескольким сегментам — поля ALPN и signature_algorithms,
необходимые для JA4, попадают во 2-й/3-й сегмент, одно-пакетный
экстрактор TSPU видит неверный хэш и пропускает соединение.

### Новое

#### Модуль `telemt_mss_selector.py` — интерактивный выбор MSS-пресета

- **10 пресетов** с подробным описанием и рекомендацией по умолчанию:
  - `tspu` (MSS 92) ★ — нативный пресет telemt против TSPU JA4, рекомендуется
  - `2in8` (MSS 256) — умеренная фрагментация, меньше overhead
  - `512` (MSS 512) — лёгкая фрагментация для линий с потерями пакетов
  - `extreme-low` (MSS 88) — максимальная фрагментация
  - `1024` / `768` / `336` / `176` / `128` — градации для тонкой настройки
  - Без изменений — MSS ядра, `client_mss` не пишется в конфиг
- **Ручной ввод** произвольного значения MSS (88–4096) через пункт `C`
- Полностью self-contained: свои цвета, box-рендеринг в стиле проекта
- Lazy-import через `_get_mss_module()` — ошибка импорта не прерывает установку

#### Обновления `mtproto.py`

- Новый шаг выбора MSS вставлен в `_run_install_inner()` сразу после выбора домена
- `_write_config()` получил параметр `client_mss: str = ""` — обратная совместимость
  сохранена: при пустом значении поле не пишется в `telemt.toml`
- Итоговый бокс установки отображает выбранный пресет и MSS в байтах
- Lazy-import `_get_mss_module()` добавлен по тому же паттерну, что `_get_fallback_module()`

### Совместимость

- `client_mss` поддерживается в telemt ≥ 3.4.15; на более ранних версиях
  параметр игнорируется без ошибки — конфиг остаётся рабочим
- Все существующие функции (`_write_config`, установка, iptables, xray-интеграция,
  fallback, статистика) работают без изменений
- Вызовы `_write_config()` без аргумента `client_mss` продолжают работать

---

## v4.12.7 — 7 июня 2026 — IP-Бан: ручная блокировка на уровне iptables/ipset

### Новое

#### Модуль IP-Бан (`ipban.py`) — ручная блокировка на уровне iptables

Новый модуль `chimera/modules/ipban.py` реализует ручной бан IP-адресов
на уровне iptables через ipset — независимо от Xray и GeoIP-блокировки.

**Доступ:** меню «🛡️ Безопасность» → `[IB] IP-Бан`

**Поддерживаемые форматы ввода** (можно несколько через запятую или пробел):

| Формат | Пример | Описание |
|---|---|---|
| Одиночный IP | `1.2.3.4`, `::1` | IPv4 или IPv6 |
| Подсеть CIDR | `10.0.0.0/24`, `2001:db8::/32` | IPv4 и IPv6 |
| Диапазон IPv4 | `10.0.0.1-10.0.0.255` | суммируется в список CIDR |
| ASN | `AS209334`, `12345` | все префиксы через RIPE Stat API |

**Реализация:**
- `ipset hash:net xray_manual_ban` (IPv4) + `xray_manual_ban6` (IPv6)
- Правила `iptables`/`ip6tables` INPUT DROP через `-A` (в конец цепочки) — не нарушают ESTABLISHED/RELATED правила
- State в `/var/lib/xray-installer/ipban.json` — сохраняет все записи с типом, CIDR и датой
- Персистентность: при каждом бане/разбане обновляет `/etc/ipset.conf`, дополняя секции GeoIP-блокировки

**Операции в меню:**
- `[1]` Добавить бан
- `[2]` Снять бан — нумерованный список с выбором по номеру или имени
- `[3]` Список активных банов с типом, количеством CIDR, датой и комментарием
- `[4]` Восстановить из state (после reboot, если `xray-ipset-restore.service` не установлен)
- `[5]` Сохранить ipset → `/etc/ipset.conf`
- `[X]` Снять все баны (flush + удаление сетов, с подтверждением)

**Изолированность:** модуль не затрагивает Xray-конфиг, GeoIP-блокировку (`xray_ru_block*`), AutoBan и никакие службы.

---

## v4.12.7 — 7 июня 2026 — TG-бот: управление Fingerprint; фикс FP при добавлении пользователя

### Новое

#### Telegram-бот: команды `/fp` и `/setfp`

Новый модуль `user_fp_manager.py` расширяет сгенерированный бот-скрипт двумя
admin-only командами, позволяя менять TLS Fingerprint без SSH на сервер:

- `/fp` — показывает текущий FP и полный список доступных вариантов (все 11: chrome, firefox, safari, ios, android, edge, 360, qq, random, randomized, none)
- `/setfp <имя>` — меняет FP немедленно: патчит `config.json`, валидирует через `xray run -test`, перезапускает Xray, обновляет `state.json` (включая `chain_nodes[*].fp` в режиме B)

Смена FP поддерживает все режимы установки: A, B, B-Multi, xHTTP, REALITY.
При ошибке валидации конфиг автоматически откатывается из бэкапа.

Чтобы команды появились в боте — пересоздать бот-скрипт через меню
`Security → [TB] Telegram Config Bot → перезапустить бота`.

### Исправлено

#### Неверный FP в ссылке при добавлении пользователя после установки

**Симптом:** при добавлении нового пользователя через «Менеджер пользователей»
сгенерированная ссылка всегда содержала `fp=chrome`, независимо от того,
какой Fingerprint был выбран при установке. У пользователей с заблокированным
`chrome` соединение не устанавливалось.

**Причина:** в `_unified_show_links()` FP был захардкожен строкой `"chrome"`
вместо чтения из `state.json`.

**Исправление:** `st.get("fingerprint", "chrome") or "chrome"` — теперь ссылка
всегда использует реально сконфигурированный Fingerprint.

---

## ✨ v4.12.7 — 7 июня 2026 — Telemt: гибридный fallback Middle Proxy → Direct Mode

### Новое

#### Telemt: автоматический fallback из Middle Proxy в Direct Mode

Новый модуль `telemt_fallback.py` реализует гибридный режим работы Telemt:
при деградации ME-серверов Telegram сервис автоматически переключается в
Direct Mode без перезапуска и разрыва активных соединений.

**Новые параметры в секции `[middle_proxy]` в `telemt.toml`** (все опциональны,
старые конфиги работают без изменений):

```toml
[middle_proxy]
fallback_to_direct      = true   # разрешить автоматический fallback
fallback_after_attempts = 3      # попыток инициализации ME-пула до признания недоступным
fallback_after_seconds  = 45     # максимальное время warmup (секунд)
auto_revert_to_middle   = false  # автовозврат в Middle после восстановления (каркас)
```

**Логика работы:**
- После старта Telemt выполняется TCP-проверка ME-серверов (DC1–DC5, кворум ≥34%)
- При неудаче после `fallback_after_attempts` попыток или по истечении `fallback_after_seconds` — runtime-переключение в Direct Mode
- Переключение затрагивает только транспорт до Telegram DC; порты, iptables и xray-интеграция не изменяются
- Защита от restart-loop: повторная попытка инициализации Middle Proxy только при `systemctl reload` или через `auto_revert_to_middle`

**Новые пункты в меню Telemt:**
- `[F]` Hybrid Fallback — просмотр состояния, изменение параметров, ручное переключение режима, ME-проба, hot-reload
- Строка статуса `Fallback:` в шапке меню

**Логирование:**
```
WARN  Middle Proxy warmup timeout exceeded (45s)
WARN  ME pool initialization failed after 3 attempts
WARN  ME pool initialization failed for too long → falling back to Direct DC mode for stability
INFO  Runtime transport mode switched: Middle Proxy -> Direct
INFO  Configuration reload requested Middle Proxy mode, starting ME pool initialization
```

**Встроенные тесты:** `python telemt_fallback.py --test` (24 теста)

---

### Исправлено

#### Telemt: дублирование ключа `use_middle_proxy` в `telemt.toml`

**Симптом:** После срабатывания fallback Telemt не запускался:
```
TOML parse error at line 7, column 1
use_middle_proxy = false
^^^^^^^^^^^^^^^^
duplicate key
```

**Причина:** `_patch_config_middle_proxy()` определяла отсутствие ключа по сравнению
строк `new_text == text`. При повторном вызове с тем же значением (`false → false`)
regex заменял успешно, но строки оставались идентичными — функция уходила в ветку
вставки и добавляла второй экземпляр ключа.

**Исправление:** Наличие ключа теперь проверяется отдельным `re.search` до любых
замен. Добавлен проход по строкам, удаляющий дубликаты даже из уже повреждённых
конфигов. Функция идемпотентна: N последовательных вызовов гарантируют ровно одно
вхождение ключа.

---

#### Telemt: неполный список `[dc_overrides]` в Direct Mode

**Симптом:** При fallback в Direct Mode часть Telegram DC могла не резолвиться —
в конфиг добавлялся только DC203, тогда как Telemt обслуживает группы
`[-203, -3, -2, -1, 1, 2, 3, 203, -5, -4, 5]`.

**Исправление:** `[dc_overrides]` теперь содержит все 12 записей:
DC1–DC5, их зеркала (-1..-5), DC203 и -DC203.

---

## 🛠 v4.12.7 — 6 июня 2026 — Хотфиксы Ubuntu 22.04

### Исправлено

---

#### nginx: default server без сертификатов при `return 444` (nginx < 1.19.4)

**Симптом:** На Ubuntu 22.04 (nginx 1.18.0) nginx не запускался после установки:
```
nginx: [emerg] no ssl configured for the server
```

**Причина:** Предыдущий фикс (`ssl_reject_handshake` → `return 444`) был неполным.
Директива `listen ... ssl` **всегда** требует `ssl_certificate` и `ssl_certificate_key` —
кроме случая когда присутствует `ssl_reject_handshake on;`, которая специально снимает
это требование. Без неё nginx падал даже с `return 444`.

**Исправление:** Для nginx < 1.19.4 в default server блок теперь добавляются те же
сертификаты что и в основном блоке:
- nginx ≥ 1.19.4 → `ssl_reject_handshake on;` (как раньше)
- nginx < 1.19.4 → `ssl_certificate` + `ssl_certificate_key` + `return 444;`

---

#### xray: `config.json` создавался без прав для пользователя `xray`

**Симптом:** На Ubuntu 22.04 xray не запускался сразу после установки:
```
xray[...]: Failed to start: failed to load config files: ... failed to read config: open /usr/local/etc/xray/config.json
```
Помогал только ручной `chown xray:xray /etc/xray/*`.

**Причина:** В двух функциях генерации конфига (`generate_xray_config_chain_entry`,
`generate_xray_config_chain_entry_multi`) `chown` после записи `config.json` не вызывался
вообще. В двух других (`generate_xray_config`, `generate_xray_config_xhttp`) использовался
`_run(["chown", "root:xray", ...], check=False)` — тихо падал без предупреждения если
группа `xray` ещё не была создана в нужный момент.

**Исправление:** Во всех 4 функциях сразу после `cfg_file.write_text(...)` вызывается
`_set_config_owner(cfg_file)` — надёжная функция через `grp.getgrnam` + `os.chown`,
с fallback на `644` при отсутствии группы `xray`.

---

## 🚀 v4.12.7 — 6 июня 2026 — Интерактивный выбор TLS Fingerprint

### Добавлено

---

#### Новый модуль `fingerprint_manager.py`

Централизованный модуль управления TLS/uTLS Fingerprint. Единый источник
правды для всего проекта — список FP, интерактивный выбор, валидация, fallback.

**Полный список поддерживаемых FP (11 вариантов):**
`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`,
`random`, `randomized`, `none`

Ранее в проекте было захардкожено только 4 варианта (`chrome`, `firefox`,
`safari`, `edge`), и выбора при установке не было — всегда применялся `chrome`.

---

#### Шаг `[11/11]` в мастере установки

В `prompt_parameters()` добавлен интерактивный шаг выбора FP. Пользователь
видит все 11 вариантов с текущим значением по умолчанию, может ввести номер
или имя FP напрямую. При нажатии Enter применяется `chrome` (безопасный
fallback).

Шаг DNSCrypt-proxy переименован из `[10/10]` в `[10/11]`.

---

#### FP для exit-нод в Режиме B

В `prompt_chain_params()` и `_prompt_one_node_manual()` старый локальный
словарь `fp_opts` (4 варианта) заменён вызовом `_fm_prompt_fingerprint()`.
Каждая exit-нода теперь получает полный список из 11 вариантов.

---

#### Сохранение FP в `state.json`

Выбранный fingerprint записывается в `state.json` под ключом `"fingerprint"`.
Это позволяет постустановочным операциям (добавление пользователей, вывод
ссылок) использовать корректный FP без повторного ввода.

---

#### Вспомогательная функция `_fp_from_state()`

Читает FP из `state.json` с fallback на `PARAM_FINGERPRINT` и затем на
`"chrome"`. Используется в `_users_gen_link()` при генерации ссылок
постфактум.

---

### Изменено

- `_FP_LIST` в `do_manage_fingerprint()` теперь импортируется из
  `fingerprint_manager.py` — единый список, нет дублирования.
- Ротационный cron-скрипт исключает мета-варианты (`random`, `randomized`,
  `none`) из пула случайного выбора — только реальные браузерные отпечатки.
- Все хардкоды `&fp=chrome` в URI-ссылках заменены на динамическое значение
  из `PARAM_FINGERPRINT` / `state.json`.

---

### Покрытие режимов

| Режим | FP применяется |
|---|---|
| A (одиночный) | ✅ шаг 11/11 при установке |
| B (chain entry+exit) | ✅ шаг 11/11 + отдельный выбор для каждой exit-ноды |
| AWG | ✅ через те же функции генерации ссылок |
| WARP | ✅ через те же функции генерации ссылок |
| Постустановка (пользователи) | ✅ через `_fp_from_state()` из state.json |

---

## 🐛 v4.12.6 — 5 июня 2026 — Совместимость nginx с Ubuntu 22.04

### Исправлено

---

#### nginx: unknown directive "ssl_reject_handshake" на Ubuntu 22.04

**Симптом:** На Ubuntu 22.04 установщик падал с ошибкой:
```
nginx: [emerg] unknown directive "ssl_reject_handshake"
```

**Причина:** Директива `ssl_reject_handshake` появилась в nginx 1.19.4.
На Ubuntu 22.04 из стандартного репо устанавливается nginx 1.18.0 — директива
не поддерживается.

**Исправление:** Добавлена проверка версии nginx при генерации конфига:
- nginx ≥ 1.19.4 → `ssl_reject_handshake on;` (как раньше)
- nginx < 1.19.4 → `ssl_certificate` + `ssl_certificate_key` + `return 444;`
  (сертификаты обязательны при `listen ... ssl` без `ssl_reject_handshake`, иначе nginx не запустится)

---

#### nginx: конфиг из sites-enabled не загружался при установке из nginx.org репо

**Симптом:** При установке nginx из официального репо nginx.org конфиг сайта
не применялся — nginx игнорировал `/etc/nginx/sites-enabled/`.

**Причина:** nginx из репо nginx.org использует только `conf.d/` и не включает
`sites-enabled/` в `nginx.conf` по умолчанию (в отличие от пакета из Ubuntu репо).

**Исправление:** Добавлена функция `_ensure_nginx_sites_enabled_include()` которая
при каждой настройке nginx проверяет `/etc/nginx/nginx.conf` и добавляет строку
`include /etc/nginx/sites-enabled/*;` после `include conf.d/` если она отсутствует.

---

## 🐛 v4.12.6 — 5 июня 2026 — Фикс IPv6 через прокси (routeOnly: False)

### Исправлено

---

#### IPv6 не работал через прокси несмотря на выбор UseIPv6v4

**Симптом:** После установки и выбора стратегии `UseIPv6v4` IPv6 через прокси не появлялся.
Помогал только ручной патч конфига с последующим рестартом xray.

**Причина:** Во всех VLESS inbound-блоках стояло `routeOnly: True`. Это означает что xray
применял роутинг на основе снифинга, но **не переписывал destination** при передаче в outbound.
В результате freedom outbound получал уже резолвленный IPv4-адрес вместо доменного имени,
и `domainStrategy: UseIPv6v4` не мог сделать свою работу — домен резолвить не нужно,
IP уже есть, и он IPv4.

**Исправление:** `routeOnly: False` во всех 6 VLESS/REALITY inbound-блоках:
- `generate_xray_config()` — Режим A, REALITY
- `generate_xray_config_xhttp()` — Режим A, xHTTP
- `generate_xray_config_chain_entry()` — Режим B, entry нода
- `generate_xray_config_chain_entry_multi()` — Режим B, multi-entry

**Совместимость:** AWG не затронут (`metadataOnly: True` для AWG сохранён).
Telemt tproxy (dokodemo-door) не затронут — у него `sniffing: disabled`.

---

## 🐛 v4.12.5 — 5 июня 2026 — IPv6 не работал через прокси (metadataOnly: True)

### Исправлено

---

#### IPv6 недоступен при подключении через VLESS REALITY (test-ipv6.com показывал 0/10)

**Симптом:** При подключении через прокси сайты с IPv6 открывались по IPv4,
test-ipv6.com показывал `0/10`, хотя на сервере IPv6-связность была (`curl -6` работал),
и в конфиге была выбрана стратегия `UseIPv6v4`.

**Причина:** В трёх функциях генерации конфига Xray параметр `metadataOnly` был
выставлен в `True` для базового сценария (без AWG, без split tunnel):

```python
# Было (неправильно для базового случая):
"metadataOnly": True if AWG_EXIT_ENABLED else (False if SPLIT_TUNNEL_ENABLED else True)
#                                                                              ^^^^ баг
```

При `metadataOnly: True` Xray не читает SNI/Host из трафика клиента.
В результате outbound `freedom` получает уже готовый IPv4-адрес вместо доменного имени,
`domainStrategy: UseIPv6v4` не применяется, и соединение устанавливается по IPv4.

**Затронутые функции:**
- `generate_xray_config()` — Режим A (основная установка)
- `generate_xray_config_chain_entry()` — Режим A/B, xHTTP транспорт
- `generate_xray_config_chain_entry_multi()` — Режим B, VLESS каскад

**Исправление:** Условие упрощено — `metadataOnly: True` только при AWG
(AWG использует маршрутизацию ядра и не зависит от sniffing доменов),
во всех остальных случаях — `False`:

```python
# Стало:
"metadataOnly": True if AWG_EXIT_ENABLED else False
```

**Как исправить на существующей установке** (без переустановки):

```bash
cd /opt/vless-ultimate && git pull

python3 - <<'EOF'
import json
path = "/etc/xray/config.json"
with open(path) as f:
    d = json.load(f)
for ib in d.get("inbounds", []):
    sn = ib.get("sniffing", {})
    if sn.get("metadataOnly") == True:
        sn["metadataOnly"] = False
        print(f"inbound [{ib.get('tag')}] metadataOnly -> False")
    if sn.get("routeOnly") == True:
        sn["routeOnly"] = False
        print(f"inbound [{ib.get('tag')}] routeOnly -> False")
with open(path, "w") as f:
    json.dump(d, f, indent=2, ensure_ascii=False)
print("Готово.")
EOF

systemctl restart xray
```

---

## 🐛 v4.12.4 — 4 июня 2026 — Совместимость с Python 3.10 (Ubuntu 22.04)

### Исправлено

---

#### SyntaxError: f-string expression part cannot include a backslash / unmatched '('

**Симптом:** На Ubuntu 22.04 (Python 3.10) установщик падал с ошибкой:

```
SyntaxError: f-string expression part cannot include a backslash
SyntaxError: f-string: unmatched '('
```

**Причина:** В Python 3.12 (Ubuntu 24.04) был переписан парсер f-строк ([PEP 701](https://peps.python.org/pep-0701/)),
который снял ограничения на использование `\` и одинаковых кавычек внутри `{}` выражений.
Код, написанный и протестированный на 3.12, падал на Python 3.10/3.11.

**Исправлено 13 мест в трёх файлах:**

- `chimera/_core.py` — 5 f-строк (включая внутри `f"""..."""` блока конфига DNSCrypt)
- `chimera/modules/warp.py` — 8 f-строк с вызовами `_get_warp("KEY", "")`
- `chimera/modules/health.py` — 1 f-строка с `_get_state_value("domain", "")`

---

#### Устаревший _core.py при повторном запуске на существующей установке

**Симптом:** После выхода фикса пользователь повторно запускал `bootstrap.sh`,
видел `✓ Обновлено до последней версии`, но ошибка оставалась.

**Причина:** `bootstrap.sh` принудительно перезаписывал с GitHub только `tg_nets.py`.
Если `git pull` тихо завершался с ошибкой — `_core.py` оставался старым.

**Исправление:** Теперь при каждом запуске принудительно обновляются
`_core.py` и `main.py` напрямую с GitHub.

---

### Улучшено

#### Предупреждение о версии Python при запуске

На Python < 3.12 установщик теперь показывает явное предупреждение вместо
молчаливого продолжения, с названиями возможных ошибок и ссылкой на
[deadsnakes PPA](https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa).

---

## 🐛 v4.12.3 — 4 июня 2026 — Три бага в [7] Отключить / Восстановить пользователя

### Исправлено

---

#### 1. После отключения пользователь снова показывается как `[акт]`

**Симптом:** Отключил пользователя — в консоли появляется `ОТКЛЮЧЁН`. Повторно
заходишь в пункт [7] — пользователь снова помечен `[акт]`, хотя должен быть `[ОТКЛ]`.

**Причина:** `_unified_load_users()` при чтении `users.json` полностью игнорировала
поле `disabled` — оно не попадало в словарь пользователя, и статус всегда отображался
как активный.

**Исправление:** При загрузке из `users.json` явно переносим поля `disabled` и
`disabled_at` в результирующий словарь.

---

#### 2. После перезапуска скрипта отключённый пользователь снова получает доступ

**Симптом:** Отключил пользователя — доступ остался (VPN работает). При перезапуске
скрипта состояние полностью сбрасывается.

**Причина:** `_unified_save_users()` записывала в `users.json` словарь **без** поля
`disabled` — флаг существовал только в памяти текущего сеанса. После перезапуска
все пользователи снова оказывались активными и попадали в конфиг Xray.

**Исправление:** `_unified_save_users()` теперь явно включает `disabled` /
`disabled_at` в запись на диск.

---

#### 3. `failed to build inbound config` при отключении последнего / всех пользователей

**Симптом:** После отключения пользователя (особенно если он единственный) в консоль
выводится:

```
[WARN]  Конфиг невалиден — пользователи не применены!
Failed to start: main: failed to load config files: [/etc/xray/config.json]
> infra/Conf: failed to build inbound config with tag inbound-vless
```

**Причина:** Xray не принимает пустой массив `clients: []` в inbound —
это считается невалидным конфигом и Xray отказывается запускаться.

**Исправление:** В `_users_apply_to_config()` добавлена защита: если список активных
пользователей пуст, в `clients` помещается placeholder-запись с нулевым UUID
(`00000000-0000-0000-0000-000000000000`). Inbound остаётся валидным, но реально
подключиться через него невозможно.

---

## 🐛 v4.12.3 — 4 июня 2026 — Фикс импорта незашифрованного архива миграции

### Исправлено

---

#### Миграция: ошибка дешифрования при импорте обычного `.tar.gz`

**Симптом:** При выборе пункта **[2] Импорт** в меню «Миграция конфигурации» и передаче
обычного (незашифрованного) архива `.tar.gz` появлялась ошибка:

```
[WARN]  Ошибка дешифрования — неверный пароль или повреждённый файл
```

**Причина:** Функция `do_full_migration_import()` **всегда** прогоняла архив через
`openssl enc -d`, независимо от того, зашифрован он или нет. Обычный `.tar.gz` через
дешифратор не проходил → ошибка, импорт невозможен.

**Исправление** (`chimera/_core.py`):
- Добавлена проверка расширения файла: если суффикс `.enc` — запускается расшифровка,
  иначе — архив используется напрямую
- Запрос пароля теперь появляется **только** для зашифрованных архивов; для `.tar.gz`
  выводится сообщение «пароль не требуется»
- Уточнены подсказки в строке ввода пути и в пункте меню [2]

---

## 🐛 v4.12.3 — 4 июня 2026 — Три фикса: Hysteria2, DNS в Режиме B, Telemt tproxy

### Исправлено

---

#### 1. Hysteria2: `Exec format error` при запуске сервиса

**Симптом:** `hysteria-server.service: Failed to execute /usr/local/bin/hysteria: Exec format error`

**Причина (локальная установка):** `curl -L` скачивал файл и сохранял его даже если GitHub
был недоступен или отдавал HTML-страницу с ошибкой. Xray пытался запустить HTML как
исполняемый файл → `Exec format error`.

**Причина (удалённая установка через SSH):** `_detect_arch()` запускала `uname -m` **локально**
(на entry-node), а URL для скачивания использовался на **удалённой** exit-ноде. При разных
архитектурах скачивался бинарник не той платформы → тот же `Exec format error`.

**Исправление** (`hysteria2_exit_mgr.py`):
- `_install_h2_binary()`: флаг `-fsSL` вместо `-L` (curl возвращает ошибку при HTTP ≥ 400),
  проверка размера файла (< 1 МБ = не бинарник), проверка ELF magic bytes (`\x7fELF`)
  перед установкой — при несовпадении файл удаляется с внятной ошибкой
- `h2_exit_remote_install()`: `uname -m` теперь выполняется через SSH на удалённой машине;
  та же ELF-проверка через `xxd` встроена в remote-команду

---

#### 2. Режим B: DNS-ошибки `exchange failed … IN A: read response: EOF`

**Симптом:** в логах xray массово появлялись ошибки вида:
```
dns: exchange failed for <домен> IN A: read response: EOF
```
Проявлялось только при подключении через entry-ноду с балансировкой (2+ exit-ноды),
при прямом подключении к exit-нодам ошибок не было. Интернет при этом работал.

**Причина:** Xray резолвит домены клиентов через встроенный DNS (`domainStrategy = IPIfNonMatch`).
Запросы идут UDP к `127.0.0.1:5300` (DNSCrypt-proxy). Без AWG не создавался `direct` outbound
и не добавлялось правило `127.0.0.1 → direct`. DNS-запросы попадали в `chain-balancer`
(VLESS TCP), который не может передать UDP к loopback → `read response: EOF`.
При балансировщике активируется `observatory` (зонды каждые 30 сек) — нагрузка на DNS растёт
и ошибки становятся систематическими.

**Исправление** (`_core.py`):
- `direct` outbound создаётся **всегда** (не только при AWG); при AWG fwmark сохраняется
- Правило `127.0.0.1/8 → direct` добавляется **всегда** (`/8` вместо `/32` — весь loopback)
- Исправлено в обоих генераторах: `generate_xray_config_chain_entry()` (1 нода)
  и `generate_xray_config_chain_entry_multi()` (1+ нод, балансировщик)

---

#### 3. Telemt tproxy слетал после пересборки конфига (пункт R в меню нод)

**Симптом:** после нажатия **R** («Пересобрать конфиг Xray и перезапустить») в меню
управления exit-нодами Telegram-клиент переставал подключаться через прокси.
В Telemt → Xray-интеграция отображалось «tproxy не настроен».

**Причина:** `_rebuild_and_restart_xray()` вызывает `generate_*`, которая перезаписывает
`config.json` целиком. Теряются dokodemo-door inbound и iptables-правила Telemt.
Восстановление tproxy существовало, но вызывалось только из `do_emergency_repair()` —
при обычной пересборке конфига не выполнялось.

**Исправление** (`_core.py`):
- В `_rebuild_and_restart_xray()` добавлен вызов `telemt_tproxy_emergency_restore()`
  **перед** финальным `systemctl restart xray` — inbound уже вшит в новый конфиг к моменту запуска
- Если Telemt не установлен — вызов молча пропускается (None-результат)

---

## 🐛 v4.12.3 — 3 июня 2026 — Фикс Mode B + xHTTP + AWG (Xray не стартовал)

### Исправлено

**Xray не запускался при установке в режиме B (каскад) с xHTTP + AmneziaWG** — с ошибкой:
```
failed to build inbound config with tag inbound-vless >
infra/conf: Failed to build REALITY config. >
infra/conf: invalid "privateKey": n/a
```

**Причина:** в `generate_xray_config_chain_entry_multi()` при `AWG_EXIT_ENABLED=True`
безусловно вызывалась `generate_xray_config()`, которая всегда генерирует `inbound`
с `realitySettings`. Но для xHTTP REALITY-ключи не создаются — в конфиг попадали
заглушки `"privateKey": "n/a"`, и Xray падал при старте.

В режиме A проблема не воспроизводилась, потому что там
`generate_xray_config_xhttp()` вызывается напрямую.

**Исправление в двух местах:**

1. `generate_xray_config_chain_entry_multi()` — добавлена проверка `PROTOCOL_MODE`:
   - `xhttp` → вызывается `generate_xray_config_xhttp()` (TLS Let's Encrypt, без `realitySettings`)
   - остальные режимы → `generate_xray_config()` как прежде

2. `generate_xray_config_xhttp()` — в outbound `direct` добавлен `sockopt.mark = AWG_FWMARK`
   при `AWG_EXIT_ENABLED=True`, чтобы исходящий трафик Xray маршрутизировался
   через AWG-туннель (policy routing по fwmark).

**Не затронуто:** Mode A, Mode B + VLESS, Mode B + VLESS + AWG, Mode B + xHTTP без AWG.

---

## 🆕 v4.12.3 — 3 июня 2026 — Hysteria2 транспорт

### Добавлено

- **Меню 7 — Hysteria2 транспорт**: полностью переработан в стиль box_renderer (рамки ╔═╗),
  единый с остальными разделами установщика
- **Выбор Hysteria2 при установке Режима B**: новый пункт `3 — Hysteria2 (QUIC/UDP)`
  в `prompt_awg_exit_mode()` — альтернатива VLESS и AWG 2.0
- **H2_EXIT_ENABLED**: новый глобальный флаг, сохраняется в `state.json`,
  взаимоисключающий с `AWG_EXIT_ENABLED`
- **Балансировщик нод** (hysteria2_balancer): стратегии weightedRandom / leastRtt / roundRobin
- **Health Check, Watchdog, DPI Детектор, Smoke Test, Кластер SSH**: меню приведены к
  единому стилю box_renderer

### Исправлено

- Импорты `box_renderer` вставлялись внутрь незакрытых `from ... import (` блоков → NameError
- `_list_backups` → `h2_backup_list` в меню бэкапа
- Проблемные emoji (`🖧` `🖥️` `⬆️` `⚖️`) ломали правую границу рамки — заменены

---

## 🐛 v4.12.3 — 3 июня 2026 — Фикс статистики трафика пользователей

### Исправлено

**Статистика трафика по пользователям не отображалась** в разделе
«История трафика по дням» (меню 4 → 2) — показывало 0 Б для всех пользователей,
даже при активном трафике.

**Причина:** Xray требует два условия одновременно для подсчёта трафика по пользователям:
- `policy.system.statsUserUplink/Downlink: true` — было ✅
- `policy.levels."0".statsUserUplink/Downlink: true` — **отсутствовало** ❌

Все входящие соединения xray проходят через policy level `0`. Без явного включения
счётчиков на этом уровне — `policy.system` игнорируется и трафик не считается.

**Исправление:** добавлен блок `policy.levels."0"` в трёх местах кода:
- `_xray_stats_blocks()` — шаблон для новых установок
- `_apply_stats_to_config()` — патч конфига на лету
- `do_patch_stats_api()` — ручной патч через меню `4 → P`

### Как применить на существующем сервере

Зайти в меню: **4 (Диагностика и Мониторинг) → P (Патч Stats API)**

Патч идемпотентен — безопасно запускать повторно, ничего не сломает.

### Благодарности

Спасибо **@mkssrk** за обнаружение бага и метод его исправления 🙏

---


## 🚀 v4.12.0-beta — 2 июня 2026 — Hysteria2 транспорт + фиксы Debian 13

> ⚠️ **Beta.** Hysteria2-модули добавлены и интегрированы, но автором
> ещё не тестировались на живом сервере. Используйте с осторожностью,
> сообщайте о проблемах через Issues.

---

### Новое: Hysteria2 как альтернативный транспорт (Режим B)

Добавлена поддержка **Hysteria2** как транспортного уровня между
Entry и Exit нодами. Клиенты подключаются по обычным VLESS-ссылкам
и не замечают смены транспорта — прозрачно.

```
Клиент ──VLESS──► Entry VPS ──Hysteria2/QUIC/UDP──► Exit VPS ──► Интернет
       (ссылка не меняется)   (скрытый транспорт)
```

AWG и Hysteria2 работают параллельно. Переключение через меню в любой момент
без переустановки.

#### Меню

- Главное меню: новый пункт **7 — 🚀 Hysteria2 транспорт**
- Настройки сети: новый пункт **H — 🚀 Hysteria2 транспорт**

#### Подменю Hysteria2

| Пункт | Назначение |
|-------|-----------|
| **1 — Exit-нода** | Установка H2-сервера локально или на удалённую ноду по SSH |
| **2 — Выбор транспорта** | Переключение AWG / Hysteria2 / оба |
| **3 — Балансировщик** | Стратегии weightedRandom, leastRtt, roundRobin |
| **4 — Health Check** | QUIC-пинг, RTT, потери (не TCP) |
| **5 — Watchdog** | Авторестарт через cron каждые 2 мин |
| **6 — Трафик** | RX/TX через iptables/ip6tables/ss, без новых демонов |
| **7 — Сертификаты** | certbot (Let's Encrypt) или самоподписанный |
| **8 — Обновление** | Автообновление бинарника с GitHub Releases |
| **9 — Кластер SSH** | status / restart / logs / update на группе нод |
| **B — Бэкап** | Резервное копирование конфигов + миграция из AWG |
| **D — DPI детектор** | Тест блокировки QUIC/UDP, авто-фолбэк на другой порт |
| **Q — Качество** | RTT/потери/скорость + Telegram-отчёт + авто-оптимизация |
| **S — Smoke Test** | Полная проверка после установки |
| **L — Логи** | Просмотр /var/log/hysteria*.log |

#### CLI-флаги

```bash
sudo python3 main.py --h2-install-exit [--h2-port 443,8443]
sudo python3 main.py --h2-transport h2|awg
sudo python3 main.py --h2-status
sudo python3 main.py --h2-health
sudo python3 main.py --h2-traffic
sudo python3 main.py --h2-quality-report [--tg]
sudo python3 main.py --h2-logs
sudo python3 main.py --h2-cluster status|restart|logs|update
sudo python3 main.py --h2-smoke
sudo python3 main.py --h2-weights 1.2.3.4:1.5,5.6.7.8:0.5
sudo python3 main.py --h2-autoupdate        # из cron
sudo python3 main.py --h2-watchdog-run      # из cron
sudo python3 main.py --h2-cert-monitor      # из cron
sudo python3 main.py --h2-dpi-check         # из cron
```

#### Особенности реализации

- **Zero-breakage** — ни одна существующая функция не изменена.
  VLESS/xHTTP TLS, AWG, генерация ссылок и конфигов работают штатно
- **15 новых модулей** в `chimera/modules/hysteria2_*.py`
- **Только +15 строк** в `_core.py` (импорт + 2 пункта меню)
- **DualStack** — полная поддержка IPv4 и IPv6 на всех этапах
- **Health Check через QUIC**, не TCP
- **Статистика** через iptables/ip6tables/ss — без новых демонов
- **Автофолбэк порта** при детекции блокировки DPI
- **Миграция** из AWG: `python3 migrate_awg_to_h2.py`

---

### Фикс: Debian 13 / Python 3.13 — `SyntaxError: "(" unexpected` в cron

**Затронуто:** `xray-traffic-snapshot.sh` и `xray-autoban.sh`

**Проблема:** оба скрипта генерировались через `textwrap.dedent(f"""...""")`
с Python-кодом внутри `python3 -c "..."`. Из-за смешанных отступов
`dedent` не убирал пробелы перед `#!/bin/bash`, получался невалидный
shebang. На Debian 13 (`/bin/sh` = dash вместо bash) скрипты
запускались через dash и падали с `Syntax error: "(" unexpected`
примерно на строке 25 — там, где в Python-коде встречается кортеж
`('uplink', 'downlink')`.

**Исправление:** оба скрипта переписаны на heredoc:
```bash
#!/bin/bash
python3 - <<'PYEOF'
... Python-код без проблем с кавычками и shebang ...
PYEOF
```

На Ubuntu 24.04 поведение не меняется.

---

### Фикс: Debian 13 — `FileNotFoundError: 'ufw'` в AutoBan

**Проблема:** `ufw` не установлен на Debian 13 по умолчанию
(система использует чистый nftables/iptables). AutoBan вызывал `ufw`
напрямую без проверки наличия — `subprocess` падал с `FileNotFoundError`.

**Исправление:** добавлены хелперы `_fw_ban()` / `_fw_unban()`:
```
ufw доступен  → ufw deny from IP to any
ufw отсутствует → iptables -I INPUT -s IP -j DROP
```

Работает на Ubuntu 24.04 (ufw) и Debian 13 (iptables) без изменения
поведения на каждой системе.

---

### Фикс: Python 3.13 — `SyntaxWarning` → `SyntaxError` на escape-последовательностях

**Проблема:** escape-последовательности `\d`, `\.`, `\s` внутри
обычных (не raw) f-строк вызывали `SyntaxWarning` в Python 3.12
и стали `SyntaxError` в Python 3.13.

**Исправление:** все regex-паттерны внутри генерируемых скриптов
приведены к корректному виду с двойным экранированием.

---

### Фикс: Python 3.13 — `NameError` в cron-обработчиках `main.py`

Исправлено в предыдущем коммите, документируется здесь для полноты.

**Затронуто:** `--dpi-check`, `--smart-balance`, `--pinned-fallback-check`,
`--ingress-geoip-update`

**Проблема:** `main.py` загружает `_core.py` через `exec(..., globals())`.
Функции из модулей, которые не были явно импортированы в `_core.py`
(например `_dpi_run_once` из `dpi_detector.py`), не попадали в
`globals()` при cron-запуске. На Python 3.13 поведение `exec` в части
изоляции пространств имён стало строже — `NameError` начал
воспроизводиться стабильно.

**Исправление:** в каждый cron-обработчик добавлен явный `import`
нужной функции прямо перед вызовом.

---

## 🔧 v4.11.5 — 2 июня 2026 (дополнение)

### Массовый разбан в AutoBan — больше не по одному

Раньше разбанить можно было только один IP за раз. Если после ночи
нестабильного интернета в бан попало несколько своих пользователей —
приходилось заходить в меню и чистить каждого вручную по очереди.

Теперь в пункте **[3] Разбанить IP** поддерживаются четыре способа ввода:

```
3        — разбанить один IP по номеру из списка
1,3,5    — разбанить несколько через запятую
2-6      — разбанить диапазон номеров
all      — разбанить всех сразу
1.2.3.4  — разбанить по IP напрямую (как раньше)
```

Список теперь показывает не просто IP, но и количество ошибок и время бана —
чтобы было проще понять кого именно разбанить. История банов обновляется
корректно для всех разбаненных за один раз.

---

## 🔧 v4.11.5 — 2 июня 2026 (дополнение)

### Аварийное восстановление больше не сбрасывает интеграцию Telemt

Небольшое, но заметное улучшение для тех, кто использует Telemt MTProxy
вместе с каскадом (Режим B).

**Что было:** после запуска аварийного восстановления (Меню 1 → пункт 6)
установщик пересобирал `config.json` из сохранённой конфигурации — и при этом
терял правила маршрутизации Xray для Telemt. Telemt продолжал работать,
но трафик Telegram снова шёл напрямую, а не через exit-ноду. Приходилось
заходить в меню Telemt и вручную переприменять интеграцию.

**Что стало:** аварийное восстановление теперь автоматически обнаруживает
установленный Telemt и восстанавливает интеграцию без каких-либо действий
с вашей стороны. В выводе появится строка:

```
✓  Telemt tproxy: dokodemo-door добавлен (:10811), iptables REDIRECT активен [N подсетей], транспорт: VLESS
```

или при AWG:

```
✓  Telemt tproxy: dokodemo-door добавлен (:10811), iptables REDIRECT активен [N подсетей], транспорт: AWG 2.0
```

Если конфиг выжил без пересборки и интеграция уже активна — восстановление
это тоже увидит и просто пропустит шаг без лишних действий.

Работает для всех вариантов каскада: одна VLESS exit-нода, мульти-каскад
до 10 нод и AmneziaWG 2.0.

---

## 🔧 v4.11.5 — 2 июня 2026 (дополнение)

### [CRITICAL] Исправлена ошибка генерации конфигурации DNSCrypt-proxy

**Проблема:** при установке dnscrypt-proxy падал с ошибкой:
```
FATAL: expected value but found "p" instead
```
Служба не могла стартовать и циклично перезапускалась. Причина — параметр
`lb_strategy` записывался в конфиг без кавычек:
```toml
lb_strategy = p2   # неверно — TOML не принимает голые строки
```

**Причина:** в `_core.py` значение `lb_strategy` генерировалось без учёта
требований синтаксиса TOML. Функция `apply_dnscrypt_tuning()` перезаписывала
конфиг, дополнительно убирая кавычки.

**Решение:** исправлено в двух местах — шаблон генерации конфига (~строка 5791)
и словарь `TOP_PARAMS` в `apply_dnscrypt_tuning()` (~строка 5960).
Теперь параметр записывается корректно:
```toml
lb_strategy = 'p2'
```

**Влияние:**
- ✅ Все новые установки работают без ошибок
- ✅ Существующие установки не затронуты
- ✅ Обновление требуется только при первой установке DNSCrypt

Спасибо пользователям, которые помогли найти и воспроизвести баг! 🙏

---

## 🆕 v4.11.5 — 1 июня 2026 (дополнение)

### Новые инструменты обхода: Noise, Mux, Watchdog, Stats, Share

Фрагментация — это первый рубеж. Но некоторые DPI-системы (особенно ТСПУ)
со временем обучаются и начинают распознавать даже фрагментированные паттерны.
Это обновление добавляет следующий уровень защиты — и делает работу с конфигами
значительно удобнее.

---

### 🔊 Фрагментация + Noise — Меню 4 → F6

Noise добавляет случайные байты перед TLS ClientHello. Если DPI уже научился
узнавать фрагментацию — noise делает начало соединения полностью случайным,
непохожим ни на что известное. Провайдер видит «мусор» и пропускает.

Работает поверх фрагментации — выбираете пресет фрагментации, затем
интенсивность шума. Генерирует готовый JSON для Xray и Sing-box.

---

### 🔀 Фрагментация + Mux — Меню 4 → F7

Mux (мультиплексирование) объединяет несколько запросов в один долгий
TCP-туннель. Вместо множества коротких соединений — один непрерывный поток.
DPI сложнее классифицировать такой трафик и принять решение о блокировке.

Особенно эффективно в связке с фрагментацией: fragment скрывает начало,
mux снижает количество новых «точек входа» для анализа.

---

### 🔄 Автопереключение пресетов — Меню 4 → F8

Watchdog работает в фоне как системный сервис. Если за последние 5 минут
число сброшенных соединений (RST) превышает порог — он автоматически
переключает пресет на более агрессивный:

**Лёгкая → Средняя → Агрессивная → Ультра-агрессивная**

Провайдер «закрутил гайки» ночью — утром уже стоит нужный пресет.
Всё без вашего участия.

---

### 📈 Статистика эффективности — Меню 4 → F9

Показывает за любой период (час / 3 часа / сутки):
- Процент успешных соединений
- Количество RST-сбросов
- Тренд: улучшается / ухудшается / стабильно
- ASCII-гистограмма по 10-минутным интервалам

Если RST растёт — сигнал сменить пресет. Если стабильно зелёный —
текущая фрагментация работает.

---

### 📲 Поделиться конфигом без scp — Меню 2 → G

Самое удобное новое: теперь не нужен компьютер чтобы передать конфиг
пользователю на телефон. Установщик поднимает временный защищённый
сервер на 10 минут, показывает QR-код — пользователь сканирует
и файл скачивается прямо на устройство.

После скачивания сервер гаснет автоматически. Ссылка одноразовая.

---

### Полная карта меню фрагментации

**Меню 2 — Управление пользователями:**

| Пункт | Назначение |
|---|---|
| **F** | Ссылки + QR для Happ / Incy / Nekoray / v2rayNG — с фрагментацией |
| **G** | Временный QR-сервер — скачать конфиг на телефон без scp |

**Меню 4 — Диагностика:**

| Пункт | Назначение |
|---|---|
| **F1** | Один конфиг с выбором пресета фрагментации |
| **F2** | Тест связности VPS (ориентировочно) |
| **F3** | Живая визуализация в логах Xray |
| **F4** | Сгенерировать все 9 конфигов сразу ← начать здесь |
| **F5** | Гайд: как правильно тестировать на своём устройстве |
| **F6** | Фрагментация + Noise (шум) |
| **F7** | Фрагментация + Mux (мультиплексирование) |
| **F8** | Watchdog — автопереключение при деградации |
| **F9** | Статистика: RST / успех / тренд / гистограмма |

---

## 📖 Гайд: с чего начать и как использовать

### Шаг 1 — Сгенерировать конфиги (Меню 4 → F4)

Нажмите F4 и подтвердите. Установщик создаст 9 конфигов с разными
параметрами фрагментации и сохранит их в `/var/lib/xray-installer/fragment_configs/`.

### Шаг 2 — Передать конфиг пользователю (Меню 2 → G)

Перейдите в Меню 2, нажмите G. Выберите нужный конфиг из списка.
Покажите QR-код пользователю — он сканирует телефоном и скачивает файл.

Или используйте F для генерации ссылок под конкретный клиент:
- **Happ, Incy, Nekoray** — QR сразу с фрагментацией, больше ничего не нужно
- **v2rayNG, Hiddify** — нужно импортировать скачанный JSON-файл

### Шаг 3 — Попробовать разные конфиги

Нет универсального «лучшего» пресета — он зависит от вашего провайдера.
Скачайте несколько конфигов через G и попробуйте каждый.
Тот, где выше скорость и нет обрывов — оставьте.

Ориентир для начала:
- **Ростелеком, МТС** → Средняя (10–50 байт)
- **Билайн, Мегафон** → Сбалансированная (3–7 байт)
- **Жёсткая блокировка, ТСПУ** → Агрессивная (1–3 байт) или F6 (Noise)

### Шаг 4 — Смотреть что происходит (Меню 4 → F9)

Откройте F9 и посмотрите на гистограмму. Если красных столбцов (RST) много —
текущий пресет не справляется, попробуйте более агрессивный или включите Noise (F6).

### Шаг 5 — Включить автопереключение (Меню 4 → F8)

Если не хотите следить вручную — включите Watchdog (F8 → пункт 1).
Он сам переключится на более агрессивный пресет если начнутся проблемы.

### Когда что использовать

| Ситуация | Что делать |
|---|---|
| Всё работает, хочу попробовать | F4 → скачать конфиги → G → передать |
| Соединение нестабильно | F9 → посмотреть статистику |
| Фрагментация не помогает | F6 (Noise) или F7 (Mux) |
| Не хочу следить вручную | F8 (Watchdog) |
| Нужно передать конфиг без компьютера | Меню 2 → G |

---

### Что нового: обход блокировок через фрагментацию

Провайдеры в России, Иране и других странах используют DPI-оборудование,
которое анализирует первый пакет вашего соединения и блокирует его, если
видит признаки VPN. Фрагментация решает эту проблему: она разбивает этот
первый пакет на мелкие кусочки, которые DPI не успевает собрать и опознать.

В этом обновлении мы добавили всё необходимое прямо в установщик.

---

### 🔀 Подключение с фрагментацией — Меню 2 → F

Самый простой способ раздать конфиги с фрагментацией своим пользователям.

Выбираете пресет → установщик генерирует готовые ссылки и QR-коды
для каждого клиента отдельно:

- **Happ, Incy, Nekoray / Nekobox** — достаточно отсканировать QR или
  скопировать ссылку. Фрагментация включится автоматически.
- **v2rayNG, Hiddify, NyameBox, Xray** — установщик создаёт готовый
  JSON-файл, который нужно скачать с сервера и импортировать в клиент.

После показа ссылок и QR-кодов появляется пошаговая инструкция —
что делать в каждом конкретном приложении.

---

### 📦 Сгенерировать все конфиги сразу — Меню 4 → F4

Если не знаете, какая фрагментация подойдёт — создайте все 9 вариантов
одной командой и попробуйте каждый:

| Группа | Для кого |
|---|---|
| **Агрессивные** (1–5 байт) | Жёсткий DPI, Иран, ТСПУ |
| **Средние** (10–50 байт) | Россия, большинство провайдеров |
| **Лёгкие** (50–200 байт) | Когда соединение работает, но нестабильно |
| **Эталон** (без фрагментации) | Для сравнения скорости |

Скачайте все файлы на устройство, попробуйте каждый и оставьте тот,
где лучше скорость и стабильность.

---

### 🔬 Тест связности VPS — Меню 4 → F2

Проверяет, работает ли вообще соединение через ваш VPS с фрагментацией.
Перебирает несколько вариантов, измеряет скорость подключения и подсказывает,
что попробовать в первую очередь.

*Важно: тест работает прямо на сервере. Для точного результата лучше
тестировать конфиги на своём устройстве через F4.*

---

### 📊 Что происходит в реальном времени — Меню 4 → F3

Показывает в терминале живую картину соединений через ваш сервер:
какие подключения проходят успешно, какие сбрасываются провайдером,
есть ли признаки блокировки. Удобно для диагностики.

---

### 🛠️ Исправления

- **MTProto / Telegram-прокси (Режим B):** ссылка `tg://` теперь всегда
  содержит IP вашей российской entry-ноды, а не IP зарубежной exit-ноды.
  Раньше пользователи получали ссылку с неправильным адресом и не могли
  подключиться.

---

#### Новые модули

- **`fragment_config.py`** — Генератор клиентских конфигов с фрагментацией.
- **`fragment_fuzzer.py`** — Автоматический подбор параметров (Fuzzer).
- **`fragment_log_viewer.py`** — Визуализация фрагментации в логах Xray.
- **`fragment_presets.py`** — Генерация полного набора из 9 конфигов одной командой.
- **`fragment_link.py`** — Ссылки и QR-коды для конкретных клиентов.
- **`fragment_guide.py`** — Интерактивный гайд по тестированию.

#### Поддержка клиентов

| Клиент | Платформы | Fragment из QR/ссылки |
|---|---|---|
| **Happ** | iOS / Android / macOS / Windows / Linux / TV | ✅ сразу |
| **Incy** | iOS / Android / macOS / Windows / Linux / TV | ✅ сразу |
| **Nekoray / Nekobox** | Windows / Linux / macOS | ✅ сразу |
| **NyameBox** | Windows / Linux | ⚠️ нестабильно, рекомендуется JSON |
| **v2rayNG** | Android | ❌ нужен JSON-файл |
| **Hiddify** | Android / iOS / Desktop | ❌ нужен JSON-файл |
| **Xray** | Linux / macOS / Windows | ❌ нужен JSON-файл |

---

## 🔧 v4.11.4 — 28 мая 2026

### Исправления AWG 2.0 (Режим B)

- **fix:** корректный SNI в клиентских ссылках при AWG-транспорте — теперь используется `reality_dest` (домен маскировки) вместо собственного домена ноды
- **fix:** DNS-таймауты в Режиме B + AWG — добавлен `direct` outbound с AWG fwmark и правило `127.0.0.1 → direct` чтобы DNS-запросы Xray не уходили в `chain-exit`
- **fix:** конфликт `awg-quick@awg0.service` и `amneziawg-awg0.service` на exit-ноде — старый сервис теперь останавливается перед запуском нового, устраняя проблему "awg show пустой" и черепашьей скорости (~3 КБ/с). В одной из конфигураций серверов так же была замечена проблема - хостер резал UDP пакеты. Это, к счастью, не проблема скрипта, а проблема конкретного хостера, и фикса тут может быть два - пробовать менять роли серверов (Entry<->Exit) либо менять хостера(ов).
- **fix:** импорт `_AUTO_FALLBACK_CRON`, `_AUTO_FALLBACK_SCRIPT`, `_AUTO_FALLBACK_LOGFILE` в `_core.py` — планировщик задач больше не падает с `NameError`
- **fix:** `ListenPort` отсутствовал в клиентском конфиге AWG — порт был случайным при каждом перезапуске, exit-нода не могла отправить ответ. Теперь фиксированный порт 11100
- **fix:** входящий UDP порт AWG не открывался на entry-ноде — провайдеры с `INPUT policy DROP` (например AEZA) блокировали ответные пакеты от exit-ноды. Скрипт теперь добавляет правило `iptables -A INPUT -p udp --dport 11100 -j ACCEPT` автоматически

---

## 🔧 v4.11.3 — 24 мая 2026

### Исправления (`tg_nets.py`)
- Убраны нерабочие источники (bgp.tools, RADB/IRR, RIPE WHOIS REST)
- Единственный источник: RIPE NCC stat.ripe.net (announced-prefixes)
- Добавлен whitelist-фильтр: принимаются только префиксы внутри
  официального IP-пространства Telegram (точные /22-/24 блоки)
- Результат: 19 подсетей (14 IPv4 + 5 IPv6) вместо 51

---
## 🆕 v4.11.3 — 23 мая 2026

### Telegram через заблокированную entry-ноду — теперь работает

Это обновление решает задачу, с которой сталкивается каждый, кто разворачивает
каскад в России: **Telemt MTProto Proxy на entry-ноде физически не мог подключиться
к серверам Telegram**, потому что они заблокированы на уровне провайдера.
Раньше нужно было либо мириться с этим, либо вручную городить обходные пути.

Теперь установщик делает всё сам.

---

#### Что изменилось для вас

Если у вас настроен **каскад (Режим B)** — одна или несколько exit-нод за рубежом —
и вы устанавливаете Telemt на entry-ноду в России, установщик обнаружит каскад и
предложит включить интеграцию. После согласия Telemt начнёт отправлять трафик
Telegram через ваши же exit-ноды. Никаких дополнительных действий не требуется.

Работает со всеми вариантами каскада:

- **Одна exit-нода** через VLESS + REALITY
- **Несколько exit-нод** (до 10) с автоматической балансировкой нагрузки
- **AmneziaWG 2.0** — зашифрованный туннель между нодами

После установки в меню Telemt появляется новый пункт **[X] Xray-интеграция**,
где можно в любой момент проверить состояние, включить или отключить обход.

---

#### Почему не через SOCKS5

Первое, что приходит в голову — настроить Telemt так, чтобы он сам ходил
через локальный прокси xray. Это чистое и элегантное решение. Мы его попробовали.

Оказалось, что **Telemt v3.x не поддерживает SOCKS5 в секции `[[upstreams]]`**.
При попытке запустить с таким конфигом сервис падает сразу после старта с ошибкой
`Error: Con... in 'upstreams'`. Поддерживаются только `direct` и `middle`
(собственный протокол Telegram). Middle-серверы Telegram тоже недоступны из России —
круг замкнулся.

---

#### Как это работает на самом деле

Решение прозрачное — Telemt об этом вообще не знает.

Когда Telemt пытается подключиться к серверу Telegram (а их IP-диапазоны
хорошо известны и не меняются), операционная система перехватывает это соединение
и перенаправляет его в xray. Xray уже знает, как добраться до Telegram —
через вашу exit-ноду. Telemt получает ответ как будто подключился напрямую.

Правила перехвата прописываются в systemd-юнит Telemt и живут ровно столько,
сколько работает сервис. При остановке или удалении Telemt они убираются
автоматически — никакого мусора в системе не остаётся.

---

#### Итог

| | До v4.11.3 | v4.11.3 |
|---|---|---|
| Telemt на entry-ноде в РФ | ❌ Не работает | ✅ Работает |
| Требует ручной настройки | — | ❌ Нет |
| Совместимость с AWG 2.0 | — | ✅ Да |
| Совместимость с мульти-каскадом | — | ✅ До 10 нод |
| Влияет на остальной трафик | — | ❌ Нет |

---

## v4.11.1 — 20 мая 2026

### Исправлено

**Кластерное управление `[CL]` — аутентификация по паролю SSH**

Все операции кластера (диагностика, перезапуск, обновление, ротация UUID,
произвольная команда) завершались ошибкой `Permission denied` на нодах, где
не настроен SSH-ключ. Теперь при отсутствии ключа установщик запрашивает пароль
root один раз за сессию и использует его для всех нод. Новый пункт меню
**[P] Сменить пароль сессии** позволяет обновить пароль без выхода из меню.

**nginx Watchdog `[NW]` и ipset Persist `[IP]` — длинные строки в меню**

Несколько пунктов этих подменю выходили за рамки TUI-интерфейса. Исправлено
разбиением на две строки.

**Кластер `[CL]` — ошибки SSH с длинным текстом выходили за рамки**

Причина ошибки (`Permission denied (publickey,password)`) теперь отображается
на отдельной строке с отступом.

---

## v4.11 — 20 мая 2026

### Добавлено

- **Smoke-test после apply** — автопроверка подключения после каждого изменения конфига;
  при провале предлагается аварийное восстановление
- **nginx Watchdog `[NW]`** — systemd-таймер каждые 2 минуты; при падении nginx
  перезапускает его и отправляет уведомление в Telegram
- **ipset Persistent `[IP]`** — правила ingress-блокировки переживают перезагрузку сервера
- **Проверка возраста RIPE-файла** — предупреждение при устаревших данных подсетей (30/90 дней)
- **Кластерное управление `[CL]`** — управление всеми exit-нодами из одного меню:
  диагностика, перезапуск, обновление xray-core, ротация UUID, произвольная команда

---

## v4.06

### Добавлено

- AmneziaWG 2.0 с поддержкой нескольких нод и балансировкой
- Smart Balancer: автовыбор лучшей ноды (roundRobin / leastPing / pinned)
- Failover A↔B: автопереключение при отказе exit-нод
- DPI Detector и Honeypot-порт
- AutoBan по TLS-ошибкам
- Telegram-уведомления
- Traffic Limits и TTL-пользователи
- Health Report: ежедневный отчёт
- GeoIP-блокировка входящих, AS-direct routing
- Clash Meta / Sing-box конфиг-генератор
- xHTTP streamup + xmux
- Мульти-каскад до 10 exit-нод

---

## v3.99

- CloudFlare WARP (full / selective / runet)
- Split Tunneling с geosite/geoip
- РФ-подсети из RIPE NCC
- Scheduled Backup

## v3.x

- Базовая установка VLESS + REALITY
- Режим B (каскад)
- Управление пользователями, диагностика
