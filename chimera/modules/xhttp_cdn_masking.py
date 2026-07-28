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
     — скрытое меню, защищённое паролем (SHA-256 hash + hmac.compare_digest).
       Plaintext-пароль в коде НЕ хранится — только hash. Админ меняет hash
       через chimera/scripts/generate_cdn_masking_password_hash.py и сообщает
       пароль платным клиентам отдельно.

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
        "mode": "auto",
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
#  СКРЫТОЕ МЕНЮ — защита паролем
# =============================================================================
# В коде хранится ТОЛЬКО SHA-256 hash пароля. Plaintext НИГДЕ не появляется:
#   • не в исходниках
#   • не в комментариях
#   • не в git-истории (мы передаём пароль юзеру в отдельном сообщении)
#
# Требования к паролю (ТЗ): ≥20 символов, заглавные + прописные + спец.символы.
#
# Админ меняет пароль так:
#   1. Запускает chimera/scripts/generate_cdn_masking_password_hash.py
#   2. Вводит новый пароль (скрипт проверяет длину/сложность)
#   3. Получает SHA-256 hash
#   4. Заменяет значение константы ниже
#   5. Коммуницирует пароль платным клиентам отдельно (не через git)
#
# Текущий hash соответствует тестовому паролю (сообщается юзеру вне кода).
_CDN_MASKING_PASSWORD_HASH: str = (
    "e84455a260273ca94b7abf6fe34540666be3cdd431910bdbc72a5b5c6a4df4d9"
)


def _core_module():
    """Ленивый импорт chimera._core — паттерн всех модулей проекта."""
    return importlib.import_module("chimera._core")


def _verify_cdn_masking_password(password: str) -> bool:
    """Проверяет пароль доступа к скрытому меню «CDN masking».

    Использует hmac.compare_digest() для constant-time сравнения —
    защита от timing-атак. Пароль НЕ хранится в коде, только его SHA-256 hash.
    """
    if not password:
        return False
    pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(pwd_hash, _CDN_MASKING_PASSWORD_HASH)


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

    success(f"Сгенерирован path: {GREEN}{_path}{NC}")
    info("Запуск полной установки профиля CDN masking...")

    try:
        # do_full_install — основная функция установки из _core.py.
        # Она вызовет prompt_protocol_mode() → пользователь выберет xhttp →
        # _prompt_xhttp_options() → do_full_install увидит XHTTP_CDN_MASKING=True
        # и использует build_xhttp_cdn_masking_inbound вместо _build_xhttp_settings.
        do_full_install = core.do_full_install
        do_full_install()
    except Exception as e:
        warn(f"Ошибка установки: {e}")
        return

    # ── Печать инструкции для Beeline CDN ─────────────────────────────────
    PARAM_DOMAIN = getattr(core, "PARAM_DOMAIN", "") or ""
    if not PARAM_DOMAIN:
        warn("Не удалось определить домен — инструкция не напечатана.")
        return

    print()
    _box_top("📖  ИНСТРУКЦИЯ: НАСТРОЙКА BEELINE CDN")
    _box_row()
    _box_desc("Эти шаги нужно выполнить ВРУЧНУЮ в панели Beeline CDN.")
    _box_desc("Установщик только генерирует origin-side конфигурацию.")
    _box_sep()
    _box_bottom()
    print()

    try:
        print_cdn_setup_instructions(PARAM_DOMAIN, _path)
    except Exception as e:
        warn(f"Ошибка печати инструкции: {e}")

    print()
    _box_top("✅  CDN MASKING УСТАНОВЛЕН")
    _box_row()
    _box_ok(f"Path:        {_path}")
    _box_ok(f"Домен:       {PARAM_DOMAIN}")
    _box_ok(f"Backend:     127.0.0.1:{CDN_MASKING_INBOUND_PORT}")
    _box_row()
    _box_sep()
    _box_row()
    _box_warn("Не забудьте настроить Beeline CDN по инструкции выше.")
    _box_bottom()
    print()
    try:
        input(f"  {CYAN}Нажмите Enter для возврата в меню...{NC}")
    except (EOFError, KeyboardInterrupt):
        pass
