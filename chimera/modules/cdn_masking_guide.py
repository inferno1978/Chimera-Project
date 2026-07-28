"""
chimera/modules/cdn_masking_guide.py
───────────────────────────────────────────────────────────────────────────────
Печать пошаговой инструкции для ручной настройки CDN Beeline (и аналогов)
при активированном профиле «CDN masking» для XHTTP.

Стиль: статический текст с f-string подстановкой сгенерированных значений
(domain, path), без интерактивности. Просто печать в stdout — пользователь
копирует и применяет в панели CDN вручную.

Аналог по стилю: singbox_menu._show_cdn_instructions() / wdtt._guide_vk_hash().
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import importlib


def _core_module():
    """Ленивый импорт chimera._core — паттерн всех модулей проекта."""
    return importlib.import_module("chimera._core")


def _print_boxed(text_lines: list[str]) -> None:
    """Печатает строки в box-стиле проекта (если _core доступен) или просто
    через print (fallback для тестов).
    """
    try:
        core = _core_module()
        _box_top = core._box_top
        _box_row = core._box_row
        _box_sep = core._box_sep
        _box_desc = core._box_desc
        _box_info = core._box_info
        _box_warn = core._box_warn
        _box_bottom = core._box_bottom
    except Exception:
        # Fallback: печать без рамок (для тестов/изолированных вызовов)
        for line in text_lines:
            print(line)
        return

    # Первая строка — заголовок, далее — тело
    if not text_lines:
        _box_top("")
        _box_bottom()
        return

    _box_top(text_lines[0])
    _box_row()
    for line in text_lines[1:]:
        if line == "":
            _box_row()
        elif line.startswith("WARN:"):
            _box_warn(line[5:].strip())
        elif line.startswith("INFO:"):
            _box_info(line[5:].strip())
        elif line.startswith("DESC:"):
            _box_desc(line[5:].strip())
        elif line.startswith("SEP:"):
            _box_sep()
        else:
            _box_row(f"  {line}")
    _box_bottom()


def print_cdn_setup_instructions(domain: str, path: str) -> None:
    """Печатает пошаговую инструкцию по настройке ресурса в Beeline CDN.

    Аргументы:
        domain — origin-домен (тот же, что в PARAM_DOMAIN / сертификате).
        path   — сгенерированный XHTTP path (например /api/v2/static.ts).

    Вывод: статический текст с подставленными domain/path, в стиле существующих
    ручных инструкций Chimera (см. wdtt._guide_vk_hash / singbox_menu.
    _show_cdn_instructions). Без интерактивности — только печать.
    """
    if not domain:
        raise ValueError("print_cdn_setup_instructions: domain не может быть пустым")
    if not path:
        raise ValueError("print_cdn_setup_instructions: path не может быть пустым")

    # Нормализуем path для подстановки в URL
    _path = path.strip()
    if not _path.startswith("/"):
        _path = "/" + _path
    # Не убираем trailing slash — path имеет формат /seg/seg.php, без trailing.

    # URL origin (CDN подключается к origin по этому адресу)
    origin_url = f"https://{domain}:443"

    # Полный URL туннеля (для проверки после настройки)
    tunnel_url = f"https://{domain}{_path}"

    # Beeline CDN: типичный адрес ЛК — https://cdn.beeline.ru (или старый
    # https://cloud.beeline.ru). Указываем оба, т.к. интерфейс мог меняться.
    instructions: list[str] = [
        f"РУЧНАЯ НАСТРОЙКА BEELINE CDN — ДОМЕН {domain}",
        "",
        "DESC:Эти шаги нужно выполнить в Личном Кабинете Beeline CDN ВРУЧНУЮ.",
        "DESC:Установщик только генерирует origin-side конфигурацию Xray+Nginx.",
        "DESC:CDN-панель не имеет публичного API для автоматизации — поэтому",
        "DESC:настройка выполняется через веб-интерфейс.",
        "SEP:",
        "",
        "ШАГ 1. Вход в ЛК Beeline CDN",
        "INFO:Откройте https://cdn.beeline.ru (или https://cloud.beeline.ru)",
        "INFO:Войдите по логину/паролю, выданному менеджером Beeline.",
        "INFO:Если раздел CDN отсутствует — обратитесь к менеджеру для",
        "INFO:активации услуги «CDN» на вашем аккаунте.",
        "",
        "ШАГ 2. Создание ресурса (CDN → Добавить ресурс)",
        "INFO:Раздел «CDN» → кнопка «Добавить ресурс» (или «Создать ресурс»).",
        f"INFO:Тип ресурса: «Статика» (Static).",
        f"INFO:Origin-адрес:  {domain}:443",
        f"INFO:Origin URL:    {origin_url}",
        "INFO:Protocol на origin: HTTPS (TLS терминирует Nginx на :443).",
        "INFO:Port на origin: 443 (стандартный HTTPS).",
        "INFO:SNI на origin: укажите явно — это ваш домен:",
        f"INFO:  SNI = {domain}",
        "",
        "ШАГ 3. Настройка HTTPS на edge (CDN ↔ клиент)",
        "INFO:В разделе ресурса → «HTTPS» / «SSL-сертификат».",
        "INFO:Выберите «Заказать сертификат Let's Encrypt» (бесплатно).",
        f"INFO:CN/SAN сертификата: {domain}",
        "INFO:Дождитесь выпуска (1-5 минут). Статус должен стать «Активен».",
        "INFO:Режим HTTPS: «Full» или «Full (strict)» — origin тоже HTTPS.",
        "",
        "ШАГ 4. Настройка кэширования",
        "INFO:В разделе «Кэширование» / «Cache settings».",
        f"INFO:Правило исключения: pathbegins с {_path}",
        f"INFO:  → Cache-Control: no-cache, no-store, must-revalidate",
        f"INFO:  → TTL: 0 секунд (НЕ кэшировать туннельный трафик!)",
        "INFO:Для всех остальных путей (статика заглушки) — дефолтный TTL.",
        "INFO:Обязательно: Disable caching для POST-запросов (иначе поток",
        "INFO:данных туннеля будет накапливаться в кэше edge).",
        "",
        "ШАГ 5. Настройка таймаутов",
        "INFO:В разделе «Дополнительно» / «Advanced» → Timeout settings.",
        "INFO:Origin Connect Timeout:   60 сек",
        "INFO:Origin Read Timeout:      3600 сек  (длинные стримы)",
        "INFO:Origin Send Timeout:      3600 сек  (длинные стримы)",
        "INFO:Client Read Timeout:      3600 сек",
        "INFO:Client Send Timeout:      3600 сек",
        "INFO:Keep-Alive Timeout:       60 сек",
        "INFO:НЕ включайте «Buffer responses» — стриминг ломается.",
        "",
        "ШАГ 6. Rewrite правила (проброс path на origin)",
        "INFO:В разделе «Rules» / «Rewrite».",
        "INFO:Создайте правило:",
        f"INFO:  IF request URI matches {_path}*",
        f"INFO:  THEN forward to origin as-is (без rewrite).",
        "INFO:Query-string: пробросить без изменений (xhttp использует ?auth=...).",
        "INFO:HTTP method: разрешить GET, POST (xhttp uplink=POST, download=GET).",
        "INFO:Headers: пробросить все входящие заголовки на origin.",
        "",
        "ШАГ 7. WebSocket / Streaming",
        "INFO:Если есть тоггл «WebSocket» — включить (xhttp stream-up)",
        "INFO:хоть xhttp и не WebSocket, но долгоживущие соединения требуют",
        "INFO:такого же режима edge (no buffering).",
        "INFO:«Streaming responses» / «Buffering» — ОТКЛЮЧИТЬ.",
        "",
        "ШАГ 8. Привязка домена (CNAME)",
        f"INFO:В DNS вашего домена создайте CNAME-запись:",
        f"INFO:  {domain}  →  <cdn-edge-hostname>.beeline.ru",
        "INFO:(cdn-edge-hostname выдаётся в ЛК после создания ресурса).",
        "INFO:Дождитесь применения DNS (TTL записи, обычно 5-15 минут).",
        "",
        "ШАГ 9. Проверка",
        f"INFO:Откройте в браузере: https://{domain}/",
        "INFO:Должна открыться fake-login заглушка (страница «Доступ к серверу»).",
        f"INFO:Откройте: https://{domain}{_path}",
        "INFO:Должна открыться пустая страница или 404 — это нормально,",
        "INFO:т.к. без XHTTP-клиента туннельный path ничего не отдаёт.",
        "INFO:Подключитесь клиентом с генерированным конфигом — должно работать.",
        "",
        "SEP:",
        "",
        "DESC:После настройки панели — клиентский конфиг уже содержит",
        "DESC:все нужные extra-поля (симметричные серверу).",
        f"DESC:Server:  {domain}",
        f"DESC:Path:    {_path}",
        f"DESC:Mode:    xhttp (auto)",
        f"DESC:Port:    443 (через CDN edge)",
        "",
        "WARN:Если CDN блокирует long-polling: проверьте SSE-заголовок.",
        "WARN:В профиле CDN masking noSSEHeader=true — должно быть ОК.",
        "WARN:Если CDN режет POST-body: проверьте, что отключён request buffering.",
        "WARN:Если DPI всё же детектит: смените path (пгенерировать новый через",
        "WARN:скрытое меню), старый инбаунд удалите.",
    ]

    _print_boxed(instructions)


# ── Self-test для ручной проверки ────────────────────────────────────────────
if __name__ == "__main__":  # pragma: no cover
    print_cdn_setup_instructions("example.com", "/api/v2/static.ts")
