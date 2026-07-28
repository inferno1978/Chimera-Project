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

    # ── Path для полей ОТКУДА/КУДА в Rewrite панели Beeline ──────────────
    # Beeline Rewrite принимает path БЕЗ ведущего '/' (например 'api/v3/segment.ts/'
    # в мануале, не '/api/v3/segment.ts/'). Это специфика парсинга правил Rewrite.
    # ОТКУДА — path с trailing '/' (для матчинга запросов с trailing slash),
    # КУДА — path без trailing '/' (нормализованный path origin).
    rewrite_from = _path.lstrip("/") + "/"
    rewrite_to = _path.lstrip("/")

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
        "INFO:Раздел «CDN» → кнопка «Добавить ресурс».",
        "INFO:Тип ресурса: «Статика».",
        f"INFO:В адрес укажите домен ноды с портом 443:  {domain}:443",
        "INFO:Нажмите «Создать».",
        "",
        "ШАГ 3. Конфигурация ресурса (раздел ресурса)",
        "INFO:Использовать HTTPS при запросе к источникам:  ВКЛ",
        f"INFO:Указать имя SNI-хоста — домен ноды:            ВКЛ  ({domain})",
        f"INFO:Hostname при запросе к источнику — домен ноды:       {domain}",
        "INFO:Кэширование:  ВЫКЛ (либо ВКЛ с TTL=0 вручную)",
        "INFO:  ↳ Кэшировать с учётом query string → Учитывать все параметры:  ВКЛ",
        "",
        "ШАГ 4. Экспертные настройки",
        "INFO:Использовать HTTP/2:  ВКЛ",
        "INFO:Использовать HTTP/3:  ВЫКЛ",
        "INFO:Автоматически перенаправлять HTTP → HTTPS:  ВКЛ",
        "INFO:Использовать только современные версии TLS:  ВКЛ",
        "INFO:Таймауты (сек):  5 / 300 / 300   (Connect / Read / Send)",
        "INFO:Проверка CORS на стороне CDN:  ВЫКЛ",
        "INFO:Сжатие Brotli:  ВЫКЛ",
        "INFO:Сжатие Gzip:  ВЫКЛ",
        "INFO:Разрешённые HTTP-методы:  POST",
        "",
        "ШАГ 5. Rewrite — ВКЛ. Пути уже подставлены под ваш path:",
        "INFO:Где выполнять rewrite:  На конечных узлах (edge)",
        "INFO:⚠️  Path уже подставлен под ваш сгенерированный path.",
        "INFO:    Если меняли path в скрытом меню — обновите и здесь.",
        "INFO:",
        f"INFO:  ОТКУДА:  {rewrite_from}",
        f"INFO:  КУДА:    {rewrite_to}",
        "INFO:",
        "INFO:Query-string пробрасывается без изменений (xhttp использует ?auth=...).",
        "INFO:HTTP-метод POST — xhttp uplink, download через GET.",
        "",
        "ШАГ 6. Привязка домена (CNAME)",
        f"INFO:В DNS вашего домена создайте CNAME-запись:",
        f"INFO:  {domain}  →  <cdn-edge-hostname>.beeline.ru",
        "INFO:(cdn-edge-hostname выдаётся в ЛК после создания ресурса).",
        "INFO:Дождитесь применения DNS (TTL записи, обычно 5-15 минут).",
        "INFO:Если ваш регистратор не разрешает CNAME на apex-домен —",
        "INFO:используйте поддомен (например cdn.<domain>) или Вариант 2",
        "INFO:(см. ШАГ 7 — клиент подключается к CDN hostname напрямую).",
        "",
        "ШАГ 7. Клиентский конфиг (ВАЖНО!)",
        "INFO:Для CDN masking используйте ТОЛЬКО sing-box JSON конфиг,",
        "INFO:не vless://-ссылку (см. предупреждение при установке).",
        "INFO:Сгенерируйте через: меню 2 → пункт 5 → /root/xray-client-configs/sing-box.json",
        "INFO:",
        "INFO:В sing-box.json поле server должно указывать на CDN edge hostname,",
        "INFO:а НЕ на домен origin. Host и SNI остаются = домен origin.",
        "INFO:  server:        <cdn-edge-hostname>  (например rfzs98suyu.a.trbcdn.net)",
        f"INFO:  transport.host: {domain}  (домен origin)",
        f"INFO:  tls.server_name: {domain}  (домен origin)",
        "INFO:",
        "INFO:CDN-edge-hostname выдается в панели Beeline CDN при создании ресурса.",
        "INFO:Если у вас нет CNAME-записи — клиент подключается напрямую к CDN hostname.",
        "",
        "ШАГ 8. Проверка",
        f"INFO:Откройте в браузере: https://{domain}/",
        "INFO:Должна открыться fake-login заглушка (страница «Доступ к серверу»).",
        f"INFO:Откройте: https://{domain}{_path}",
        "INFO:Должна открыться пустая страница или 404 — это нормально,",
        "INFO:т.к. без XHTTP-клиента туннельный path ничего не отдаёт.",
        "INFO:Подключитесь клиентом с sing-box JSON конфигом — должно работать.",
        "",
        "ШАГ 9. Финал",
        "INFO:После всех действий — произведите полную очистку кэша на CDN-ресурсе.",
        "",
        "SEP:",
        "",
        "DESC:После настройки панели — клиентский конфиг уже содержит",
        "DESC:все нужные extra-поля (симметричные серверу).",
        f"DESC:Server:  {domain}",
        f"DESC:Path:    {_path}",
        "DESC:Mode:    xhttp (auto)",
        "DESC:Port:    443 (через CDN edge)",
        "",
        "WARN:Если CDN блокирует long-polling: проверьте SSE-заголовок.",
        "WARN:В профиле CDN masking noSSEHeader=true — должно быть ОК.",
        "WARN:Если CDN режет POST-body: проверьте, что отключён request buffering.",
        "WARN:Если DPI всё же детектит: смените path (сгенерировать новый через",
        "WARN:скрытое меню), старый инбаунд удалите, обновите ОТКУДА/КУДА в Rewrite.",
    ]

    _print_boxed(instructions)


# ── Self-test для ручной проверки ────────────────────────────────────────────
if __name__ == "__main__":  # pragma: no cover
    print_cdn_setup_instructions("example.com", "/api/v2/static.ts")
