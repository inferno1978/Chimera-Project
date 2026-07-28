"""
chimera/modules/xhttp_cdn_masking.py
───────────────────────────────────────────────────────────────────────────────
Профиль «CDN masking» для XHTTP — экспертные параметры маскировки под
реальный HTTPS-трафик через CDN Beeline (и аналоги).

СОСТАВ:
  1. CDN_MASKING_INBOUND_PORT  — loopback-порт Xray-инбаунда
  2. CDN_MASKING_EXTRA         — словарь xhttpSettings.extra (сервер+клиент
                                  симметричны, значения — константы)
  3. CDN_MASKING_HEADERS       — HTTP-заголовки браузерной мимикрии
  4. build_xhttp_cdn_masking_inbound(domain, path, port=7443) -> dict
     — возвращает ПОЛНЫЙ streamSettings.xhttpSettings для серверного
       инбаунда (включая path/host/extra). Не заменяет существующий
       _build_xhttp_settings() из _core.py — это отдельный профиль.
  5. build_xhttp_cdn_masking_client_extra() -> dict
     — клиентская копия extra-блока (для client_config_export /
       users_manager._gen_vless_link).
  6. _unlock_cdn_masking_menu() / run_cdn_masking_install()
     — скрытое меню, защищённое паролем. Хеш пароля хранится ТОЛЬКО
       в state-файле на сервере (/var/lib/xray-installer/cdn_premium.hash),
       НИКОГДА не в исходниках и не в git. Используется PBKDF2-HMAC-SHA256
       со случайной солью и 600000 итераций (OWASP 2025-2026), проверка
       через hmac.compare_digest (constant-time). Plaintext-пароля нет
       нигде в репозитории. Админ устанавливает/меняет пароль через
       chimera/scripts/generate_cdn_masking_password_hash.py, который
       пишет хеш прямо в state-файл (chmod 0600, root).

СПРАВКА: профиль «CDN masking» — опциональный. Текущий простой XHTTP-режим
(path+mode) остаётся дефолтным и не затрагивается. Профиль активируется
только через скрытое меню (ввод кода доступа).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import hashlib
import hmac
import getpass
import importlib
import json
import os
from pathlib import Path
from typing import Any


# =============================================================================
#  ТОПОЛОГИЯ — loopback-порт Xray-инбаунда для CDN masking
# =============================================================================
# Серверный Nginx терминирует TLS на :443, отдаёт заглушку (включая новый
# шаблон _create_fake_login) для location /, и проксирует location {path}
# на 127.0.0.1:CDN_MASKING_INBOUND_PORT. Это отдельный порт от
# XHTTP_BACKEND_PORT (8443), чтобы простой и CDN-masking профили не
# конфликтовали при одновременном (гипотетическом) включении.
CDN_MASKING_INBOUND_PORT: int = 7443

# ── XHTTP mode для CDN masking профиля ─────────────────────────────────────
# Валидные значения xhttpSettings.mode по документации Xray-core:
#   "auto", "packet-up", "stream-up", "stream-one"
# (все, кроме auto, через дефис). Значения "stream-up"/"stream-one"/"packet-up"
# (слитно) — ОПЕЧАТКИ, которых Xray не знает.
#
# CDN masking использует "auto" — Xray сам выбирает stream-up/packet-up по
# HTTP-методу запроса (POST → packet-up uplink, GET → stream-up download).
# Это позволяет одному инбаунду обслуживать оба режима, что соответствует
# референс-конфигу «Beeline CDN XHTTP node».
#
# Эта константа используется в ДВУХ местах:
#   1. build_xhttp_cdn_masking_inbound() — пишет в server config.json
#   2. run_cdn_masking_install() — setattr(core, "XHTTP_MODE", ...) чтобы
#      клиентская ссылка (vless://...&mode=...) получила то же значение.
# Если когда-либо измените mode — измените ОДНУ константу, оба места
# синхронизируются автоматически.
_CDN_MASKING_XHTTP_MODE: str = "auto"

# host-заголовок для CDN masking. При пустой строке Xray использует SNI.
# Для Beeline CDN: SNI = внешний домен CDN, host = origin-домен (тот же
# домен, что и в PARAM_DOMAIN) — обычно совпадают, оставляем пустым.
CDN_MASKING_HOST: str = ""


# =============================================================================
#  ЭКСПЕРТНЫЕ ПАРАМЕТРЫ МАСКИРОВКИ — xhttpSettings.extra
# =============================================================================
# Значения — константы, идентичные серверу и клиенту (симметрия обязательна:
# любое расхождение ломает handshake). Не спрашиваем юзера про каждое поле —
# это экспертные дефолты, откалиброванные по гайду «Beeline CDN XHTTP node».
CDN_MASKING_EXTRA: dict[str, Any] = {
    # ── xPadding — случайный padding в заголовках запросов/ответов ─────────
    # Уменьшает fingerprint по фиксированной длине заголовка.
    # Референс: xPaddingBytes(50-150), xPaddingHeader("X-Api-Key"),
    # xPaddingMethod("tokenish"), xPaddingObfsMode(true), xPaddingPlacement("header")
    "xPaddingBytes":       "50-150",
    "xPaddingHeader":      "X-Api-Key",
    "xPaddingMethod":      "tokenish",
    "xPaddingObfsMode":    True,
    "xPaddingPlacement":   "header",

    # ── Sequence — последовательность пакетов с ключом ──────────────────────
    # seqKey="chunk_id", seqPlacement="query" — идентификатор сессии в URL.
    "seqKey":              "chunk_id",
    "seqPlacement":        "query",

    # ── Session — привязка соединения к сессии ──────────────────────────────
    # sessionIDKey="auth", sessionIDTable="Base62", sessionIDLength="16-32",
    # sessionPlacement+sessionIDPlacement="query"
    "sessionKey":          "session",
    "sessionIDKey":        "auth",
    "sessionIDTable":      "Base62",
    "sessionIDLength":     "16-32",
    "sessionPlacement":    "query",
    "sessionIDPlacement":  "query",

    # ── Заголовки ответа: отключить SSE и gRPC Content-Type ────────────────
    # noSSEHeader=true — не отдавать text/event-stream (CDN может блокировать).
    # noGRPCHeader=true — не отдавать application/grpc (фильтрация DPI).
    "noSSEHeader":         True,
    "noGRPCHeader":        True,

    # ── Stream-up / packet-up лимиты (только сервер) ───────────────────────
    # Референс: scMaxBufferedPosts(100) / scMaxEachPostBytes(3000000) /
    # scMinPostsIntervalMs("5-10") / scMaxConcurrentPosts(10)
    "scMaxBufferedPosts":     100,
    "scMaxEachPostBytes":     3000000,
    "scMinPostsIntervalMs":   "5-10",
    "scMaxConcurrentPosts":   10,

    # serverMaxHeaderBytes — лимит размера заголовков на сервере.
    "serverMaxHeaderBytes":   32768,

    # ── HTTP-методы и placement ────────────────────────────────────────────
    # uplinkHTTPMethod="POST" — клиент шлёт данные через POST.
    # downloadHTTPMethod="GET" — сервер отдаёт данные через GET.
    # uplinkDataPlacement="body" — данные в теле запроса (не в query).
    "uplinkHTTPMethod":       "POST",
    "downloadHTTPMethod":     "GET",
    "uplinkDataPlacement":    "body",

    # ── xmux — мультиплексирование proxy-потоков внутри HTTP/2 ─────────────
    # Референс: xmux.maxConcurrency("1") — ровно 1 параллельный поток на
    # соединение (маскировка под простой браузерный запрос, без H2-multiplex).
    "xmux": {
        "maxConcurrency": "1",
    },
}


# =============================================================================
#  HTTP-ЗАГОЛОВКИ БРАУЗЕРНОЙ МИМИКРИИ
# =============================================================================
# Заголовки добавляются в HTTP-запросы клиента так, чтобы на стороне CDN/DPI
# трафик выглядел как реальный браузерный запрос к API. Значения — типичные
# для Chrome 120+ на Linux/Windows.
CDN_MASKING_HEADERS: dict[str, str] = {
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                                 "image/avif,image/webp,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language":           "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cookie":                    "",
    "Origin":                    "",       # подставляется клиентом = https://<domain>
    "Referer":                   "",       # подставляется клиентом = https://<domain>/
    "User-Agent":                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                 "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Sec-Fetch-Dest":            "empty",
    "Sec-Fetch-Mode":            "cors",
    "Sec-Fetch-Site":            "same-origin",
    "Sec-Fetch-User":            "?1",
}


# =============================================================================
#  ПОСТРОИТЕЛЬ СЕРВЕРНОГО xhttpSettings (для xray_install.py)
# =============================================================================
def build_xhttp_cdn_masking_inbound(domain: str, path: str,
                                     port: int = CDN_MASKING_INBOUND_PORT) -> dict:
    """Возвращает полный streamSettings.xhttpSettings для серверного инбаунда
    в профиле «CDN masking».

    Аргументы:
        domain — домен origin (он же SNI); используется для host-заголовка,
                 если CDN_MASKING_HOST пуст.
        path   — сгенерированный через xhttp_path_gen.generate_decoy_path()
                 путь (например /api/v2/static.ts).
        port   — loopback-порт инбаунда (по умолч. 7443).

    Возвращаемый словарь имеет структуру:
        {
          "mode": "auto",            # xHTTP auto-detect (stream-up + packet-up)
          "path": "/api/v2/static.ts",
          "host": "<domain>",        # если CDN_MASKING_HOST пуст — domain
          "extra": { ...CDN_MASKING_EXTRA... }
        }

    Эта функция НЕ заменяет _build_xhttp_settings() из _core.py — это
    отдельный профиль. Вызывается только при выборе «CDN masking» в
    скрытом меню.
    """
    if not path:
        raise ValueError("build_xhttp_cdn_masking_inbound: path не может быть пустым")
    if not domain:
        raise ValueError("build_xhttp_cdn_masking_inbound: domain не может быть пустым")

    # Нормализуем path: ведущий / обязателен, без trailing slash.
    _path = path.strip()
    if not _path.startswith("/"):
        _path = "/" + _path
    _path = _path.rstrip("/") or "/"

    xhttp: dict[str, Any] = {
        # mode="auto" — Xray сам выбирает stream-up/packet-up по запросу.
        # Это позволяет одному инбаунду обслуживать оба режима (uplink POST +
        # download GET), что соответствует референс-конфигу.
        # Используем _CDN_MASKING_XHTTP_MODE (константа) — то же значение
        # используется в run_cdn_masking_install() для синхронизации с
        # клиентской ссылкой. Если изменить здесь — изменится и там.
        "mode": _CDN_MASKING_XHTTP_MODE,
        "path": _path,
        "host": CDN_MASKING_HOST or domain,
        "extra": _copy_extra_for_server(),
    }
    # port не входит в xhttpSettings — он на уровне inbound.port.
    # Но мы возвращаем его в мета-поле "__port" для удобства интеграции
    # с nginx_setup (location-блок проксирует на этот порт). Поле начинается
    # с "__" чтобы Xray его игнорировал (Xray игнорирует неизвестные поля,
    # но мы перестраховываемся — клиентский _copy_extra_for_client() это
    # поле выкидывает).
    xhttp["__backend_port"] = port
    return xhttp


def _copy_extra_for_server() -> dict[str, Any]:
    """Глубокая копия CDN_MASKING_EXTRA для серверного инбаунда.

    Серверная копия идентична константе — все поля валидны для сервера.
    """
    import copy
    return copy.deepcopy(CDN_MASKING_EXTRA)


# =============================================================================
#  ПОСТРОИТЕЛЬ КЛИЕНТСКОГО extra (для client_config_export / users_manager)
# =============================================================================
def build_xhttp_cdn_masking_client_extra() -> dict[str, Any]:
    """Возвращает extra-блок для клиентского XHTTP-конфига.

    Симметричен серверному CDN_MASKING_EXTRA, но БЕЗ сервер-only полей:
      • scMaxBufferedPosts, scMaxConcurrentPosts, serverMaxHeaderBytes,
        scMaxEachPostBytes (серверные лимиты буферизации — на клиенте не нужны)
      • scMinPostsIntervalMs (сервер может рекомендовать, но клиент
        использует свое значение; для симметрии с референсом оставляем).

    Референс-конфиг содержит эти поля и на клиенте (Xray игнорирует
    неизвестные серверные поля), поэтому мы возвращаем ПОЛНУЮ копию —
    так клиентский и серверный конфиги визуально совпадают, что
    упрощает отладку.
    """
    import copy
    return copy.deepcopy(CDN_MASKING_EXTRA)


def build_xhttp_cdn_masking_client_xhttp_settings(domain: str, path: str) -> dict:
    """Возвращает клиентский xhttpSettings (для sing-box/hiddify JSON).

    Структура:
        {
          "mode": "auto",
          "path": "<path>",
          "host": "<domain>",
          "extra": { ...симметричен серверу... }
        }
    """
    if not path:
        raise ValueError("build_xhttp_cdn_masking_client_xhttp_settings: path пуст")
    if not domain:
        raise ValueError("build_xhttp_cdn_masking_client_xhttp_settings: domain пуст")
    _path = path.strip()
    if not _path.startswith("/"):
        _path = "/" + _path
    _path = _path.rstrip("/") or "/"
    return {
        "mode": "auto",
        "path": _path,
        "host": CDN_MASKING_HOST or domain,
        "extra": build_xhttp_cdn_masking_client_extra(),
    }


# =============================================================================
#  СКРЫТОЕ МЕНЮ — защита паролем (PBKDF2, state-file на сервере)
# =============================================================================
# Хеш пароля хранится ТОЛЬКО в state-файле на диске сервера:
#   /var/lib/xray-installer/cdn_premium.hash  (chmod 0600, root)
#
# Паттерн аналогичен другим state-файлам Chimera:
#   HEALTH_CHECK_FILE = Path("/var/lib/xray-installer/health.status")
#   STATE_FILE        = Path("/var/lib/xray-installer/state.json")
#   — тот же каталог /var/lib/xray-installer/, те же права 0600.
#
# В файле — JSON: {"salt": "<hex>", "hash": "<hex>",
#                  "iterations": N, "algo": "pbkdf2_sha256"}.
# Все параметры (включая iterations и algo) хранятся В ФАЙЛЕ, не в коде —
# это позволяет в будущем поднять iterations без поломки старых хешей
# (старые файлы просто остаются с меньшим N и работают до пересоздания).
#
# КЛЮЧЕВЫЕ ГАРАНТИИ (vs. предыдущей версии с SHA-256-в-коде):
#   • Хеш НИКОГДА не попадает в git (публичный репозиторий GitHub+GitLab).
#   • Хеш НИКОГДА не попадает в git-историю (смена пароля = перезапись
#     файла на сервере, без коммита).
#   • Атакующий, получивший копию репозитория, не имеет ничего для
#     офлайн-перебора — файла с хешем у него нет.
#   • PBKDF2-HMAC-SHA256 с 600000 итераций + случайная соль 16 байт —
#     медленный хеш, GPU-брутфорс дороже на ~5 порядков чем SHA-256.
#   • При отсутствии файла (новая установка, профиль не активирован)
#     верификация всегда возвращает False — раздел скрытого меню
#     остаётся закрытым. Это соответствует исходному ТЗ: "функция
#     не активирована".
#
# 600000 итераций — актуальная рекомендация OWASP для PBKDF2-HMAC-SHA256
# на 2025-2026. Можно поднять до 1200000 при апгрейде железа; нельзя
# опускать ниже 100000.
CDN_MASKING_HASH_FILE: Path = Path("/var/lib/xray-installer/cdn_premium.hash")

# Дефолтное число итераций для НОВЫХ хешей. Старые файлы читают своё
# значение из JSON (см. _verify_cdn_masking_password — если ключ
# "iterations" отсутствует, это старый формат, см. ниже).
_CDN_MASKING_DEFAULT_ITERATIONS: int = 600_000

# Алгоритм хеширования. Хранится также в файле — при будущем переходе
# на argon2/scrypt старые файлы можно отличить по полю "algo".
_CDN_MASKING_ALGO: str = "pbkdf2_sha256"


def _core_module():
    """Ленивый импорт chimera._core — паттерн всех модулей проекта."""
    return importlib.import_module("chimera._core")


def _verify_cdn_masking_password(password: str) -> bool:
    """Проверяет пароль доступа к скрытому меню «CDN masking».

    Схема (state-file на сервере, PBKDF2-HMAC-SHA256):
      1. Если CDN_MASKING_HASH_FILE не существует → return False
         (профиль не активирован, раздел остаётся скрытым).
      2. Читает JSON, берёт salt/hash/iterations.
      3. computed = pbkdf2_hmac("sha256", password, salt, iterations).hex()
      4. hmac.compare_digest(computed, stored_hash) — constant-time.

    ОБРАБОТКА СТАРОГО ФОРМАТА (миграция с несолёного SHA-256):
      Если в JSON отсутствует ключ "iterations" или "algo" — это старый
      формат от ДО PBKDF2-фикса. Верификация НЕ пытается сравнить как
      SHA-256 (это ослабило бы гарантию и пропустило уязвимые хеши).
      Вместо этого возвращается False, а в лог пишется предупреждение
      (админ должен пересоздать пароль через generate_..._hash.py).
      Автоматическая миграция SHA-256→PBKDF2 без участия админа запрещена
      ТЗ — это ослабило бы гарантию.

    Любая ошибка (битый JSON, отсутствующие ключи, permission denied)
    → return False. Не бросает исключение наружу, не выдаёт существование
    или состояние раздела через traceback.
    """
    if not password:
        return False

    # Шаг 1: файл должен существовать.
    try:
        if not CDN_MASKING_HASH_FILE.exists():
            return False
    except Exception:
        # Любая ошибка при проверке существования файла (permission, OSError)
        # — тихо возвращаем False, не выдаём состояние раздела.
        return False

    # Шаг 2: читать и парсить JSON.
    try:
        raw_text = CDN_MASKING_HASH_FILE.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except Exception:
        # Битый JSON, файл недоступен для чтения, и т.п. — тихо False.
        return False

    # Шаг 3: проверить, что это новый формат (PBKDF2), а не старый (SHA-256).
    # Если "iterations" или "algo" отсутствуют — это старый формат.
    # Возвращаем False + лог предупреждения. НЕ пытаемся сравнить как SHA-256.
    if "iterations" not in data or "algo" not in data:
        try:
            core = _core_module()
            log_to_file = getattr(core, "log_to_file", None)
            if log_to_file is not None:
                log_to_file(
                    "WARN",
                    "CDN masking: обнаружен устаревший формат hash-файла "
                    "(отсутствует 'iterations'/'algo'). Пересоздайте пароль "
                    "через chimera/scripts/generate_cdn_masking_password_hash.py"
                )
        except Exception:
            pass  # лог недоступен — тихо возвращаем False
        return False

    # Шаг 4: проверить, что algo — это pbkdf2_sha256. Если в будущем появится
    # другой algo (argon2 и т.п.) — тут будет ветвление. Сейчас поддерживаем
    # только pbkdf2_sha256; неизвестный algo → False (не падать).
    algo = data.get("algo")
    if algo != _CDN_MASKING_ALGO:
        return False

    # Шаг 5: извлечь salt, hash, iterations. Любая ошибка → False.
    try:
        salt_hex = data["salt"]
        stored_hash = data["hash"]
        iterations = int(data["iterations"])
        salt = bytes.fromhex(salt_hex)
    except Exception:
        return False

    # Шаг 6: вычислить PBKDF2-HMAC-SHA256 от введённого пароля.
    try:
        computed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        ).hex()
    except Exception:
        return False

    # Шаг 7: constant-time сравнение.
    return hmac.compare_digest(computed, stored_hash)


def _unlock_cdn_masking_menu() -> bool:
    """Запрашивает у пользователя код доступа и проверяет его.

    Возвращает True, если пароль верный (можно открыть меню), иначе False.
    Использует getpass.getpass() — ввод без эха (как для SSH-пароля).
    """
    core = _core_module()
    try:
        CYAN = core.CYAN
        NC = core.NC
        YELLOW = core.YELLOW
        _box_top = core._box_top
        _box_bottom = core._box_bottom
        _box_row = core._box_row
        _box_sep = core._box_sep
        _box_warn = core._box_warn
        _box_info = core._box_info
    except Exception:
        # Минимальные fallback-значения если _core недоступен (тесты)
        CYAN = "\033[0;36m"
        NC = "\033[0m"
        YELLOW = "\033[1;33m"
        _box_top = lambda *a, **kw: None
        _box_bottom = lambda *a, **kw: None
        _box_row = lambda *a, **kw: None
        _box_sep = lambda *a, **kw: None
        _box_warn = lambda *a, **kw: None
        _box_info = lambda *a, **kw: None

    import os
    os.system("clear")
    print()
    _box_top("🔒  РЕЗЕРВНЫЙ РАЗДЕЛ — АВТОРИЗАЦИЯ")
    _box_row()
    _box_info("Доступ к этому разделу ограничен. Введите код доступа.")
    _box_row()
    _box_sep()
    _box_row()
    _box_warn("Неверный код — раздел останется скрытым.")
    _box_bottom()
    print()

    try:
        pwd = getpass.getpass(f"  {CYAN}Код доступа:{NC} ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    if _verify_cdn_masking_password(pwd):
        return True

    print(f"\n  {YELLOW}Неверный код доступа.{NC}")
    try:
        import time
        time.sleep(2)
    except Exception:
        pass
    return False


def run_cdn_masking_install() -> None:
    """Точка входа в скрытое меню «CDN masking».

    1. Запрашивает пароль (3 попытки).
    2. При успехе — запускает установку профиля CDN masking:
       • генерирует путь через xhttp_path_gen.generate_decoy_path()
       • переключает PROTOCOL_MODE в xhttp + включает флаг XHTTP_CDN_MASKING
       • вызывает _prompt_cdn_masking_options() для ввода домена/email
       • запускает do_full_install() с этим профилем
       • в конце печатает инструкцию по настройке Beeline CDN
    """
    # 3 попытки ввода пароля — protection от brute-force в интерактиве.
    for _attempt in range(3):
        if _unlock_cdn_masking_menu():
            break
        if _attempt == 2:
            return
    else:
        return

    # ── Пароль верный — открываем меню ────────────────────────────────────
    core = _core_module()
    _box_top = core._box_top
    _box_bottom = core._box_bottom
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_item = core._box_item
    _box_desc = core._box_desc
    _box_ok = core._box_ok
    _box_warn = core._box_warn
    _box_info = core._box_info
    CYAN = core.CYAN
    NC = core.NC
    GREEN = core.GREEN
    warn = core.warn
    success = core.success
    info = core.info

    import os
    os.system("clear")
    print()
    _box_top("☁️  CDN MASKING — ОБХОД БЕЛЫХ СПИСКОВ ЧЕРЕЗ BEELINE CDN")
    _box_row()
    _box_desc("Профиль XHTTP с экспертыми параметрами маскировки под реальный")
    _box_desc("HTTPS-трафик через CDN Beeline (и аналоги).")
    _box_row()
    _box_sep()
    _box_row()
    _box_desc("Что произойдёт:")
    _box_item("1", "Сгенерируется случайный path (формат /api/v2/static.ts)")
    _box_item("2", "Серверный Xray получит инбаунд с expert extra-полями")
    _box_item("3", "Nginx настроит reverse-proxy + fake-login заглушку")
    _box_item("4", "Клиентский конфиг получит симметричные extra-поля")
    _box_item("5", "В конце — пошаговая инструкция для панели Beeline CDN")
    _box_row()
    _box_sep()
    _box_row()
    _box_warn("Это НЕ заменяет простой XHTTP-режим — это отдельный профиль.")
    _box_bottom()
    print()

    try:
        from chimera.modules.cdn_masking_guide import print_cdn_setup_instructions
        from chimera.modules.xhttp_path_gen import generate_decoy_path
    except ImportError as e:
        warn(f"Не удалось импортировать модули CDN masking: {e}")
        return

    # ── Запуск полной установки с профилем CDN masking ────────────────────
    # Включаем флаг XHTTP_CDN_MASKING в core — его читают:
    #   • xray_install.generate_xray_config_xhttp()  (выбирает build_xhttp_cdn_masking_inbound)
    #   • nginx_setup.setup_nginx_final()            (cdn_masking_mode=True)
    #   • client_config_export / users_manager       (client extra)
    setattr(core, "XHTTP_CDN_MASKING", True)
    setattr(core, "PROTOCOL_MODE", "xhttp")
    setattr(core, "INSTALL_MODE", "A")

    # Генерируем path сразу — нужен для отображения и для do_full_install
    _path = generate_decoy_path()
    setattr(core, "XHTTP_PATH", _path)
    setattr(core, "XHTTP_BACKEND_PORT", CDN_MASKING_INBOUND_PORT)

    # ── Синхронизация XHTTP_MODE между сервером и клиентской ссылкой ──────
    # build_xhttp_cdn_masking_inbound() жёстко ставит mode=_CDN_MASKING_XHTTP_MODE
    # ("auto") в server config.json. Клиентская ссылка (vless://...&mode=...)
    # берёт значение из core.XHTTP_MODE → state["xhttp_mode"]. Если НЕ
    # выставить XHTTP_MODE здесь, останется дефолт "stream-up" → клиент
    # получит mode=stream-up → РАССИНХРОН с сервером (auto) → не подключится.
    #
    # _prompt_xhttp_options() в _core.py при XHTTP_CDN_MASKING=True НЕ
    # переспрашивает mode (аналогично path) — использует это значение.
    # Если бы переспрашивал, и пользователь выбрал бы "stream-up", то
    # client link получил бы mode=stream-up, а server config остался
    # mode=auto → рассинхрон → клиент не подключится.
    setattr(core, "XHTTP_MODE", _CDN_MASKING_XHTTP_MODE)

    success(f"Сгенерирован path: {GREEN}{_path}{NC}")
    info("Запуск полной установки профиля CDN masking...")

    # ── Вызов do_full_install ─────────────────────────────────────────────
    # ВАЖНО: do_full_install в конце печатает блок «УСТАНОВКА ЗАВЕРШЕНА»
    # и сразу возвращается в main_menu(), который делает os.system("clear").
    # Если тут возникнет исключение — мы его ловим, печатаем traceback для
    # отладки, но НЕ return-им сразу: инструкция Beeline CDN всё равно
    # печатается (origin-side конфиг может быть частично готов, и инструкция
    # нужна для ручной настройки CDN-панели).
    install_exception: Exception | None = None
    try:
        do_full_install = core.do_full_install
        do_full_install()
    except Exception as e:
        install_exception = e
        # Печатаем traceback полностью — пользователь должен видеть ЧТО упало.
        import traceback
        warn(f"Ошибка установки: {e}")
        warn("Полный traceback (для отладки):")
        for line in traceback.format_exc().splitlines()[-15:]:
            warn(f"  {line}")

    # ── Пауза после установки — пользователь видит финальный статус ───────
    # Без этой паузы main_menu() сразу сделал бы os.system("clear") и затёр
    # блок «УСТАНОВКА ЗАВЕРШЕНА». Даём пользователю время прочитать.
    print()
    try:
        input(f"  {CYAN}Нажмите Enter чтобы увидеть инструкцию по Beeline CDN...{NC}")
    except (EOFError, KeyboardInterrupt):
        pass

    # ── Предупреждение: vless:// НЕДОСТАТОЧНО для CDN masking ────────────
    # Экспертные extra-параметры (xPaddingBytes, seqKey, sessionIDKey и т.д.)
    # физически не кодируются в vless://-URI — формат share-ссылки не
    # поддерживает вложенные extra-объекты. Они доступны только через
    # sing-box JSON конфиг (через client_config_export.py).
    # Реальный пользователь (zvshka) взял vless://-ссылку — стандартный,
    # первый попавшийся способ подключиться — и не смог, потому что для
    # CDN masking этого недостаточно.
    print()
    _box_top("⚠️  ВАЖНО: КАКОЙ КОНФИГ ИСПОЛЬЗОВАТЬ КЛИЕНТУ")
    _box_row()
    _box_warn("Для профиля CDN masking НЕДОСТАТОЧНО обычной vless://-ссылки!")
    _box_row()
    _box_desc("Экспертные параметры (xPaddingBytes, seqKey, sessionIDKey,")
    _box_desc("xPaddingHeader, noSSEHeader, noGRPCHeader, xmux и т.д.)")
    _box_desc("физически не кодируются в vless://-URI — формат share-ссылки")
    _box_desc("не поддерживает вложенные extra-объекты.")
    _box_row()
    _box_desc("Эти параметры доступны ТОЛЬКО через sing-box JSON конфиг.")
    _box_row()
    _box_row(f"  {BOLD}Используйте:{NC} меню 2 → Управление пользователями →")
    _box_row(f"           {CYAN}«Экспорт для sing-box»{NC} (не «Скопировать vless-ссылку»)")
    _box_row(f"           Файл: /root/xray-client-configs/sing-box.json")
    _box_row()
    _box_warn("Без sing-box JSON конфига клиент подключится, но маскировка")
    _box_warn("не сработает — DPI увидит обычный XHTTP без padding/session.")
    _box_bottom()
    print()
    try:
        input(f"  {CYAN}Нажмите Enter для продолжения...{NC}")
    except (EOFError, KeyboardInterrupt):
        pass

    # ── Печать инструкции для Beeline CDN ─────────────────────────────────
    # Печатается ВСЕГДА — даже если do_full_install упал. Если домен не
    # определён (упали на самом первом шаге), используем заглушку.
    PARAM_DOMAIN = getattr(core, "PARAM_DOMAIN", "") or ""

    print()
    _box_top("📖  ИНСТРУКЦИЯ: НАСТРОЙКА BEELINE CDN")
    _box_row()
    _box_desc("Эти шаги нужно выполнить ВРУЧНУЮ в панели Beeline CDN.")
    _box_desc("Установщик только генерирует origin-side конфигурацию.")
    if install_exception is not None:
        _box_row()
        _box_warn("⚠️  Установка завершилась с ошибкой (см. выше). Инструкция")
        _box_warn("    всё равно показана — origin-side конфиг может быть частично готов.")
        _box_warn("    После исправления ошибки — настройте Beeline CDN по шагам ниже.")
    if not PARAM_DOMAIN:
        _box_row()
        _box_warn("⚠️  Домен не определён (установка прервалась рано). В шагах")
        _box_warn("    ниже замените '<domain>' на ваш реальный домен.")
        PARAM_DOMAIN = "<domain>"
    _box_sep()
    _box_bottom()
    print()

    # Печатаем инструкцию и ОДНОВРЕМЕННО сохраняем в файл — чтобы
    # пользователь мог прочитать её позже (после того как main_menu
    # сделает clear и затрёт вывод).
    import io
    import contextlib
    _guide_buf = io.StringIO()
    try:
        # Дублируем вывод: и в stdout (для интерактива), и в буфер (для файла)
        with contextlib.redirect_stdout(_guide_buf):
            print_cdn_setup_instructions(PARAM_DOMAIN, _path)
        # Печатаем содержимое буфера в stdout
        guide_text = _guide_buf.getvalue()
        print(guide_text, end="")
    except Exception as e:
        warn(f"Ошибка печати инструкции: {e}")
        guide_text = f"Ошибка генерации инструкции: {e}\n"

    # ── Сохраняем инструкцию в файл на диске ──────────────────────────────
    # Файл переживает os.system("clear") — пользователь всегда может
    # прочитать его через cat /root/cdn_masking_instructions.txt
    try:
        guide_file = Path("/root/cdn_masking_instructions.txt")
        guide_file.write_text(
            f"=== CDN MASKING — ИНСТРУКЦИЯ ПО НАСТРОЙКЕ BEELINE CDN ===\n"
            f"Path: {_path}\n"
            f"Domain: {PARAM_DOMAIN}\n"
            f"Backend: 127.0.0.1:{CDN_MASKING_INBOUND_PORT}\n"
            f"Дата: {__import__('datetime').datetime.now().isoformat()}\n"
            f"{'=' * 60}\n\n"
            f"{guide_text}\n",
            encoding="utf-8",
        )
        try:
            os.chmod(guide_file, 0o600)
        except Exception:
            pass
        info(f"Инструкция сохранена в файл: {guide_file}")
        info(f"  cat {guide_file}  — прочитать позже")
    except Exception as e:
        warn(f"Не удалось сохранить инструкцию в файл: {e}")

    print()
    _box_top("✅  CDN MASKING — ИТОГ")
    _box_row()
    _box_ok(f"Path:        {_path}")
    _box_ok(f"Домен:       {PARAM_DOMAIN}")
    _box_ok(f"Backend:     127.0.0.1:{CDN_MASKING_INBOUND_PORT}")
    if install_exception is not None:
        _box_row()
        _box_warn("⚠️  Установка завершилась с ошибкой — см. traceback выше.")
        _box_warn("    Сервисы могут быть не запущены. Проверьте:")
        _box_warn("      journalctl -u xray -n 50 --no-pager")
        _box_warn("      journalctl -u nginx -n 50 --no-pager")
    _box_row()
    _box_sep()
    _box_row()
    _box_info(f"Инструкция по Beeline CDN — выше и в файле /root/cdn_masking_instructions.txt")
    _box_warn("Не забудьте настроить Beeline CDN по инструкции.")
    _box_bottom()
    print()
    try:
        input(f"  {CYAN}Нажмите Enter для возврата в меню...{NC}")
    except (EOFError, KeyboardInterrupt):
        pass
