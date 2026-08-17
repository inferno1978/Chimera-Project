"""
chimera/modules/install_prompts.py
───────────────────────────────────────────────────────────────────────────────
Интерактивные запросы параметров установки.

Содержит 4 функции, вынесенные из _core.py:
  • ``prompt_parameters()``      — большая (~385 строк) функция, опрашивающая
    пользователя по 11 пунктам (UUID, ShortID, REALITY-ключи, SpiderX, сокет,
    домен, email, domainStrategy, шаблон сайта, DNSCrypt, fingerprint).
    Мутирует глобалы ядра: ``PARAM_UUID``, ``PARAM_SHORTID``,
    ``PARAM_PRIVATE_KEY``, ``PARAM_PUBLIC_KEY``, ``PARAM_SPIDERX``,
    ``PARAM_SOCKET_PATH``, ``PARAM_DOMAIN``, ``PARAM_EMAIL``,
    ``PARAM_DOMAIN_STRATEGY``, ``PARAM_SITE_TEMPLATE``, ``PARAM_USE_DNSCRYPT``,
    ``PARAM_FINGERPRINT``, ``PRIVATE_KEY_MODE``.
  • ``prompt_install_mode()``    — выбор одиночный сервер (A) или каскад (B);
    мутирует ``INSTALL_MODE``.
  • ``prompt_protocol_mode()``   — выбор VLESS+REALITY или VLESS+xHTTP+TLS +
    выбор порта; мутирует ``PROTOCOL_MODE``, ``SERVER_PORT``, ``XHTTP_PORT``.
  • ``prompt_awg_exit_mode()``   — выбор транспорта для exit-ноды (VLESS/AWG/H2)
    + параметры AWG-обфускации + метод SSH-аутентификации; мутирует
    ``AWG_EXIT_ENABLED``, ``AWG_EXIT_HOST``, ``AWG_EXIT_PORT``, ``AWG_JC`` и
    прочие ``AWG_*``, ``AWG_SSH_AUTH_METHOD``, ``AWG_SSH_PASSWORD``,
    ``PARAM_REALITY_DEST``, ``H2_EXIT_ENABLED``.

Точки входа из _core.py:
    from chimera.modules.install_prompts import (
        prompt_parameters, prompt_install_mode, prompt_protocol_mode,
        prompt_awg_exit_mode,
    )

Глобалы ядра мутируются через dual-form паттерн:
    X = value
    setattr(core, "X", X)
Это сохраняет и локальную переменную (для последующих чтений в той же
функции), и атрибут модуля ``_core`` (для других модулей).

Доступ к helpers ядра (``_box_*``, ``info``/``warn``/``success``, ``gen_uuid``,
``gen_hex``, ``gen_spiderx``, ``_fm_prompt_fingerprint``, ``STATE_FILE``,
ANSI-цвета, ``IS_IPV6_AVAILABLE``, ``XHTTP_*``, ``SERVER_PORT``,
``PROTOCOL_MODE``, ``AWG_*``, ``_prompt_xhttp_options``,
``_prompt_awg_additional_nodes``, ``getpass``) — через importlib.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import getpass
import random
import re
from pathlib import Path


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  ИНТЕРАКТИВНЫЙ ЗАПРОС ПАРАМЕТРОВ
# =============================================================================
def prompt_parameters() -> None:
    core = _core_module()
    # ── Bind helpers ──────────────────────────────────────────────────────────
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_desc   = core._box_desc
    _box_link   = core._box_link
    info    = core.info
    warn    = core.warn
    success = core.success
    gen_uuid    = core.gen_uuid
    gen_hex     = core.gen_hex
    gen_spiderx = core.gen_spiderx
    _fm_prompt_fingerprint = core._fm_prompt_fingerprint
    # ── Bind globals (for reads) ───────────────────────────────────────────────
    PROTOCOL_MODE         = core.PROTOCOL_MODE
    PARAM_FINGERPRINT     = core.PARAM_FINGERPRINT
    PRIVATE_KEY_MODE      = core.PRIVATE_KEY_MODE
    IS_IPV6_AVAILABLE     = core.IS_IPV6_AVAILABLE
    STATE_FILE            = core.STATE_FILE
    SERVER_PORT           = core.SERVER_PORT
    XHTTP_MODE            = core.XHTTP_MODE
    XHTTP_PATH            = core.XHTTP_PATH
    XHTTP_PERF_PRESET     = core.XHTTP_PERF_PRESET
    XHTTP_PADDING_BYTES           = core.XHTTP_PADDING_BYTES
    XHTTP_NO_SSE_HEADER           = core.XHTTP_NO_SSE_HEADER
    XHTTP_NO_GRPC_HEADER          = core.XHTTP_NO_GRPC_HEADER
    XHTTP_HOST                    = core.XHTTP_HOST
    XHTTP_SC_STREAM_UP_SERVER_SECS = core.XHTTP_SC_STREAM_UP_SERVER_SECS
    XHTTP_SC_MAX_EACH_POST_BYTES   = core.XHTTP_SC_MAX_EACH_POST_BYTES
    XHTTP_SC_MIN_POSTS_INTERVAL_MS = core.XHTTP_SC_MIN_POSTS_INTERVAL_MS
    XHTTP_SC_MAX_BUFFERED_POSTS    = core.XHTTP_SC_MAX_BUFFERED_POSTS
    XHTTP_XMUX_ENABLED             = core.XHTTP_XMUX_ENABLED
    XHTTP_XMUX_MAX_CONCURRENCY     = core.XHTTP_XMUX_MAX_CONCURRENCY
    XHTTP_TCP_NO_DELAY             = core.XHTTP_TCP_NO_DELAY
    XHTTP_ENABLE_SESSION_RESUMPTION = core.XHTTP_ENABLE_SESSION_RESUMPTION
    # ── Bind colors ────────────────────────────────────────────────────────────
    BLUE    = core.BLUE
    CYAN    = core.CYAN
    GREEN   = core.GREEN
    YELLOW  = core.YELLOW
    MAGENTA = core.MAGENTA
    BOLD    = core.BOLD
    DIM     = core.DIM
    NC      = core.NC

    _box_top(f"Настройка параметров установки")
    _box_row()

    # --- 0. Email + Name пользователя (по умолчанию раньше создавался
    #     "безымянный" дефолтный юзер, что приводило к путанице при удалении
    #     и замене. Теперь спрашиваем сразу — это имя будет использоваться
    #     в User Portal, Admin Panel, users.json, QR-кодах, подписке.
    #     Работает для всех режимов: A/B, VLESS/xHTTP. ---
    _box_sep()
    _box_row(f" {BLUE}[1/12] Email администратора:{NC}")
    _box_row(f" {DIM}Используется в User Portal, Admin Panel, QR-кодах, подписке.{NC}")
    _box_row(f" {DIM}Никаких email не отправляется — это просто идентификатор.{NC}")
    _box_item("1", f"Ввести вручную (рекомендуется, например: ivan@example.com)")
    _box_item("2", f"Использовать дефолтный: {DIM}admin@chimera.local{NC}")
    _box_bottom()
    while True:
        try:
            choice = input("   Выбор [1/2]: ").strip() or "1"
        except KeyboardInterrupt:
            print(); raise
        if choice == "1":
            while True:
                try:
                    v = input("   Email: ").strip()
                except KeyboardInterrupt:
                    print(); raise
                if v and "@" in v and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
                    PARAM_USER_EMAIL = v
                    setattr(core, "PARAM_USER_EMAIL", PARAM_USER_EMAIL)
                    success(f"   Email: {PARAM_USER_EMAIL}")
                    break
                warn("   Некорректный email (формат: name@domain.tld)")
            break
        elif choice == "2":
            PARAM_USER_EMAIL = "admin@chimera.local"
            setattr(core, "PARAM_USER_EMAIL", PARAM_USER_EMAIL)
            success(f"   Email: {PARAM_USER_EMAIL}")
            break
        else:
            warn("   Введите 1 или 2")

    # --- 0b. Имя (никнейм) — берётся из email-local-part по умолчанию,
    #     но можно переопределить. Используется в device_label и
    #     идентификации устройства в User Portal. ---
    _box_top(f" {BLUE}[2/12] Имя (никнейм) пользователя:{NC}")
    _default_name = PARAM_USER_EMAIL.split("@")[0] if "@" in PARAM_USER_EMAIL else "admin"
    _box_item("1", f"Использовать «{_default_name}» (из email) — рекомендуется")
    _box_item("2", f"Ввести вручную")
    _box_bottom()
    while True:
        try:
            choice = input(f"   Выбор [1/2]: ").strip() or "1"
        except KeyboardInterrupt:
            print(); raise
        if choice == "1":
            PARAM_USER_NAME = _default_name
            setattr(core, "PARAM_USER_NAME", PARAM_USER_NAME)
            success(f"   Имя: {PARAM_USER_NAME}")
            break
        elif choice == "2":
            while True:
                try:
                    v = input("   Имя: ").strip()
                except KeyboardInterrupt:
                    print(); raise
                if v and re.match(r'^[A-Za-z0-9_\-\.]{2,32}$', v):
                    PARAM_USER_NAME = v
                    setattr(core, "PARAM_USER_NAME", PARAM_USER_NAME)
                    success(f"   Имя: {PARAM_USER_NAME}")
                    break
                warn("   Имя: 2-32 символа, латиница/цифры/_-. (без пробелов)")
            break
        else:
            warn("   Введите 1 или 2")

    # --- 1. UUID ---
    _box_sep()
    _box_row(f" {BLUE}[3/12] UUID клиента:{NC}")
    auto_uuid = gen_uuid()
    _box_item("1", f"Сгенерировать автоматически: {DIM}{auto_uuid}{NC}")
    _box_item("2", f"Ввести вручную")
    _box_bottom()
    while True:
        try:
            choice = input("   Выбор [1/2]: ").strip() or "1"
        except KeyboardInterrupt:
            print()
            raise
        if choice == "1":
            PARAM_UUID = auto_uuid
            setattr(core, "PARAM_UUID", PARAM_UUID)
            success(f"   UUID: {PARAM_UUID}")
            break
        elif choice == "2":
            _box_bottom()
            while True:
                try:
                    v = input("   UUID: ").strip()
                except KeyboardInterrupt:
                    print()
                    raise
                if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v):
                    PARAM_UUID = v
                    setattr(core, "PARAM_UUID", PARAM_UUID)
                    success(f"   UUID: {PARAM_UUID}")
                    break
                warn("   Неверный UUID (формат: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
            break
        else:
            warn("   Введите 1 или 2")

    # --- 2. ShortID ---
    _box_top(f" {BLUE}[4/12] ShortID (REALITY):{NC}")
    auto_sid = gen_hex(8)
    _box_item("1", f"Сгенерировать автоматически: {DIM}{auto_sid}{NC}")
    _box_item("2", f"Ввести вручную (hex, чётная длина 2-16)")
    _box_bottom()
    while True:
        try:
            choice = input("   Выбор [1/2]: ").strip() or "1"
        except KeyboardInterrupt:
            print()
            raise
        if choice == "1":
            PARAM_SHORTID = auto_sid
            setattr(core, "PARAM_SHORTID", PARAM_SHORTID)
            success(f"   ShortID: {PARAM_SHORTID}")
            break
        elif choice == "2":
            _box_bottom()
            while True:
                try:
                    v = input("   ShortID (hex, 2-16 символов): ").strip()
                except KeyboardInterrupt:
                    print()
                    raise
                if re.match(r'^[0-9a-f]{2,16}$', v) and len(v) % 2 == 0:
                    PARAM_SHORTID = v
                    setattr(core, "PARAM_SHORTID", PARAM_SHORTID)
                    success(f"   ShortID: {PARAM_SHORTID}")
                    break
                warn("   Неверный ShortID (нужна hex строка чётной длины 2-16)")
            break
        else:
            warn("   Введите 1 или 2")

    # --- 3. Ключи REALITY (только для REALITY) ---
    key_mode = "auto"
    if PROTOCOL_MODE == "reality":
        _box_top(f" {BLUE}[5/12] Ключи REALITY (x25519) — будут сгенерированы после установки Xray:{NC}")
        _box_item("1", f"Сгенерировать автоматически (рекомендуется)")
        _box_item("2", f"Ввести вручную (если уже есть пара ключей)")
        _box_bottom()
        while True:
            try:
                choice = input("   Выбор [1/2]: ").strip() or "1"
            except KeyboardInterrupt:
                print()
                raise
            if choice == "1":
                key_mode = "auto"
                info("   Ключи будут сгенерированы после установки Xray")
                break
            elif choice == "2":
                key_mode = "manual"
                _box_bottom()
                while True:
                    try:
                        PARAM_PRIVATE_KEY = input("   Private Key: ").strip()
                    except KeyboardInterrupt:
                        print()
                        raise
                    if len(PARAM_PRIVATE_KEY) >= 40:
                        break
                    warn("   Private Key слишком короткий (мин. 40 символов)")
                setattr(core, "PARAM_PRIVATE_KEY", PARAM_PRIVATE_KEY)
                _box_bottom()
                while True:
                    try:
                        PARAM_PUBLIC_KEY = input("   Public Key:  ").strip()
                    except KeyboardInterrupt:
                        print()
                        raise
                    if len(PARAM_PUBLIC_KEY) >= 40:
                        break
                    warn("   Public Key слишком короткий (мин. 40 символов)")
                setattr(core, "PARAM_PUBLIC_KEY", PARAM_PUBLIC_KEY)
                success("   Ключи введены вручную")
                break
            else:
                warn("   Введите 1 или 2")
    else:
        info("[5/12] Ключи REALITY: пропущено (xHTTP TLS использует TLS-сертификат Let's Encrypt)")

    # --- 4. SpiderX (только для REALITY) ---
    if PROTOCOL_MODE == "reality":
        _box_top(f" {BLUE}[6/12] SpiderX (путь краулера REALITY):{NC}")
        auto_spx = gen_spiderx()
        _box_item("1", f"Сгенерировать автоматически: {DIM}{auto_spx}{NC}")
        _box_item("2", f"Ввести вручную")
        _box_bottom()
        while True:
            try:
                choice = input("   Выбор [1/2]: ").strip() or "1"
            except KeyboardInterrupt:
                print()
                raise
            if choice == "1":
                PARAM_SPIDERX = auto_spx
                setattr(core, "PARAM_SPIDERX", PARAM_SPIDERX)
                success(f"   SpiderX: {PARAM_SPIDERX}")
                break
            elif choice == "2":
                _box_bottom()
                while True:
                    try:
                        v = input("   SpiderX (начинается с /): ").strip()
                    except KeyboardInterrupt:
                        print()
                        raise
                    if v.startswith('/'):
                        PARAM_SPIDERX = v
                        setattr(core, "PARAM_SPIDERX", PARAM_SPIDERX)
                        success(f"   SpiderX: {PARAM_SPIDERX}")
                        break
                    warn("   Путь должен начинаться с /")
                break
            else:
                warn("   Введите 1 или 2")
    else:
        PARAM_SPIDERX = gen_spiderx()   # значение не используется, но задаём
        setattr(core, "PARAM_SPIDERX", PARAM_SPIDERX)
        info(f"[6/12] SpiderX: пропущено (xHTTP TLS)")

    # --- 5. Unix Socket (только для REALITY) ---
    if PROTOCOL_MODE == "reality":
        # Переиспользуем сокет из xray конфига или state.json если уже установлено
        _existing_sock = ""
        try:
            import json as _json
            _xray_cfg = _json.loads(Path("/etc/xray/config.json").read_text())
            for _inb in _xray_cfg.get("inbounds", []):
                _dest = _inb.get("streamSettings", {}).get("realitySettings", {}).get("dest", "")
                if _dest and _dest.endswith(".socket"):
                    _existing_sock = _dest
                    break
        except Exception:
            pass
        if not _existing_sock and STATE_FILE.exists():
            try:
                _existing_sock = _json.loads(STATE_FILE.read_text()).get("socket", "")
            except Exception:
                pass
        auto_sock = _existing_sock if _existing_sock else f"/dev/shm/{gen_hex(4)}.socket"
        _box_top(f" {BLUE}[7/12] Unix socket path:{NC}")
        _box_item("1", f"Использовать: {DIM}{auto_sock}{NC}")
        _box_item("2", f"Ввести вручную")
        _box_bottom()
        while True:
            try:
                choice = input("   Выбор [1/2]: ").strip() or "1"
            except KeyboardInterrupt:
                print()
                raise
            if choice == "1":
                PARAM_SOCKET_PATH = auto_sock
                setattr(core, "PARAM_SOCKET_PATH", PARAM_SOCKET_PATH)
                success(f"   Socket: {PARAM_SOCKET_PATH}")
                break
            elif choice == "2":
                _box_bottom()
                while True:
                    try:
                        v = input("   Socket path (абсолютный, .socket): ").strip()
                    except KeyboardInterrupt:
                        print()
                        raise
                    if v.startswith('/') and v.endswith('.socket'):
                        PARAM_SOCKET_PATH = v
                        setattr(core, "PARAM_SOCKET_PATH", PARAM_SOCKET_PATH)
                        success(f"   Socket: {PARAM_SOCKET_PATH}")
                        break
                    warn("   Путь должен быть абсолютным и заканчиваться на .socket")
                break
            else:
                warn("   Введите 1 или 2")
    else:
        PARAM_SOCKET_PATH = f"/dev/shm/{gen_hex(4)}.socket"  # заглушка
        setattr(core, "PARAM_SOCKET_PATH", PARAM_SOCKET_PATH)
        info(f"[7/12] Unix socket: пропущено (xHTTP TLS не использует сокет)")

    # --- 6. Домен ---
    _box_top(f" {BLUE}[8/12] Домен (SNI):{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   Домен (напр. example.com): ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if not v:
            warn("   Домен не может быть пустым")
            continue
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$', v):
            PARAM_DOMAIN = v
            setattr(core, "PARAM_DOMAIN", PARAM_DOMAIN)
            success(f"   Домен: {PARAM_DOMAIN}")
            break
        warn("   Некорректный домен. Введите FQDN вида my.example.com")

    # --- 7. Email ---
    _box_top(f" {BLUE}[9/12] Email для Let's Encrypt:{NC}")
    _box_bottom()
    while True:
        try:
            v = input(f"   Email [admin@{PARAM_DOMAIN}]: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        PARAM_EMAIL = v if v else f"admin@{PARAM_DOMAIN}"
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', PARAM_EMAIL):
            setattr(core, "PARAM_EMAIL", PARAM_EMAIL)
            success(f"   Email: {PARAM_EMAIL}")
            break
        warn("   Некорректный email")

    # --- 8. domainStrategy ---
    _box_top(f" {BLUE}[10/12] Стратегия исходящих соединений:{NC}")
    if IS_IPV6_AVAILABLE:
        _box_row(f"   {GREEN}ℹ IPv6 обнаружен на сервере{NC}")
    _box_item("1", f"UseIPv6v4 — сначала IPv6, fallback IPv4 {GREEN}(рекомендуется){NC}")
    _box_item("2", f"UseIPv4v6 — сначала IPv4, fallback IPv6")
    _box_item("3", f"UseIP     — системный DNS")
    _box_item("4", f"UseIPv4   — только IPv4")
    strat_map = {"1": "UseIPv6v4", "2": "UseIPv4v6", "3": "UseIP", "4": "UseIPv4"}
    _box_bottom()
    while True:
        try:
            choice = input("   Выбор [1]: ").strip() or "1"
        except KeyboardInterrupt:
            print()
            raise
        if choice in strat_map:
            PARAM_DOMAIN_STRATEGY = strat_map[choice]
            setattr(core, "PARAM_DOMAIN_STRATEGY", PARAM_DOMAIN_STRATEGY)
            break
        warn("   Введите 1, 2, 3 или 4")
    success(f"   domainStrategy: {PARAM_DOMAIN_STRATEGY}")

    # --- 9. Шаблон сайта ---
    _box_top(f" {BLUE}[11/12] Шаблон сайта-заглушки:{NC}")
    _box_item("1",  f"TechHub             — IT-портал (RU) · fade-up reveal")
    _box_item("2",  f"NexCloud            — serverless SaaS · gradient mesh")
    _box_item("3",  f"Holm & Oak          — homeware store · parallax")
    _box_item("4",  f"Ember & Grain       — wood-fired bistro · steam rise")
    _box_item("5",  f"NexHub              — community + storage · card flip")
    _box_item("6",  f"ByteForge           — developer forum · code rain")
    _box_item("7",  f"Lumen Architects    — architecture studio · line draw")
    _box_item("8",  f"Verdant Botanical   — plant shop · leaf sway")
    _box_item("9",  f"Northwind Coffee    — coffee roastery · steam wisps")
    _box_item("10", f"Solstice Wellness   — spa & wellness · breathing pulse")
    _box_item("11", f"Atelier Meridian    — design studio · shape morph")
    _box_item("12", f"Harborline Logistics— shipping & freight · wave motion")
    _box_item("13", f"Quietude Library    — digital library · page flip")
    _box_item("14", f"Mensara Consulting  — strategy consulting · slide reveal")
    _box_item("15", f"Cascade Analytics   — analytics SaaS · data flow")
    _box_item("0",  f"Случайный")
    _box_bottom()
    while True:
        try:
            choice = input("   Выбор [0]: ").strip() or "0"
        except KeyboardInterrupt:
            print()
            raise
        if choice == "0":
            PARAM_SITE_TEMPLATE = str(random.randint(1, 15))
            setattr(core, "PARAM_SITE_TEMPLATE", PARAM_SITE_TEMPLATE)
            break
        elif choice.isdigit() and 1 <= int(choice) <= 15:
            PARAM_SITE_TEMPLATE = choice
            setattr(core, "PARAM_SITE_TEMPLATE", PARAM_SITE_TEMPLATE)
            break
        warn("   Введите 0-15")

    # Имена шаблонов берутся из единого источника (nginx_setup_templates),
    # чтобы меню, сводка и финальный статус всегда показывали одно и то же.
    from chimera.modules.nginx_setup_templates import get_template_names
    tmpl_names = get_template_names()
    success(f"   Шаблон: {tmpl_names[int(PARAM_SITE_TEMPLATE)]}")

    # --- 10. DNSCrypt-proxy ---
    _box_top(f" {BLUE}[12/12] DNSCrypt-proxy (зашифрованный DNS):{NC}")
    _box_item("Y", f"Установить DNSCrypt-proxy {GREEN}(рекомендуется){NC}")
    _box_desc(f"Шифрует DNS-запросы, защищает от слежки провайдера")
    _box_item("N", f"Использовать публичные DNS напрямую (1.1.1.1 / 8.8.8.8)")
    _box_desc(f"Проще, меньше компонентов, чуть быстрее первый запрос")
    _box_row()
    _box_bottom()
    while True:
        try:
            choice = input("   Установить DNSCrypt-proxy? [Y/n]: ").strip().lower()
        except KeyboardInterrupt:
            print()
            raise
        if choice in ('y', 'yes', ''):
            PARAM_USE_DNSCRYPT = True
            setattr(core, "PARAM_USE_DNSCRYPT", PARAM_USE_DNSCRYPT)
            success("   DNSCrypt-proxy: будет установлен")
            break
        elif choice in ('n', 'no'):
            PARAM_USE_DNSCRYPT = False
            setattr(core, "PARAM_USE_DNSCRYPT", PARAM_USE_DNSCRYPT)
            info("   DNSCrypt-proxy: пропускаем, используем публичные DNS")
            break
        warn("   Введите Y или N")

    # --- 11. Fingerprint ---
    _box_top(f" {BLUE}[12/12] TLS Fingerprint (uTLS):{NC}")
    _box_row(f"   Определяет, под какой браузер маскируется TLS-хендшейк клиента.")
    _box_row(f"   Влияет на обход DPI. Должен совпадать в клиенте и на сервере.")
    _box_bottom()
    PARAM_FINGERPRINT = _fm_prompt_fingerprint(current=PARAM_FINGERPRINT)
    setattr(core, "PARAM_FINGERPRINT", PARAM_FINGERPRINT)

    # --- Сводка ---
    _box_bottom()
    _box_top(f"Сводка параметров")
    _box_row()
    proto_str = f"xHTTP TLS (mode={XHTTP_MODE}, path={XHTTP_PATH}, preset={XHTTP_PERF_PRESET})" if PROTOCOL_MODE == "xhttp" else "VLESS + TCP + REALITY"
    _box_row(f"  {CYAN}Протокол:{NC}        {proto_str}")
    if PROTOCOL_MODE == "xhttp":
        _box_row(f"  {CYAN}xPaddingBytes:{NC}   {XHTTP_PADDING_BYTES}")
        _box_row(f"  {CYAN}noSSEHeader:{NC}     {XHTTP_NO_SSE_HEADER}")
        _box_row(f"  {CYAN}noGRPCHeader:{NC}    {XHTTP_NO_GRPC_HEADER}")
        if XHTTP_HOST:
            _box_row(f"  {CYAN}host:{NC}            {XHTTP_HOST}")
        if XHTTP_MODE in ("stream-up", "stream-one", "auto"):
            _box_row(f"  {CYAN}StreamUpSrvSecs:{NC} {XHTTP_SC_STREAM_UP_SERVER_SECS}")
        if XHTTP_MODE in ("packet-up", "auto"):
            _box_row(f"  {CYAN}MaxEachPostBytes:{NC}{XHTTP_SC_MAX_EACH_POST_BYTES}")
            _box_row(f"  {CYAN}MinPostsIntervalMs:{NC}{XHTTP_SC_MIN_POSTS_INTERVAL_MS}")
            _box_row(f"  {CYAN}MaxBufferedPosts:{NC}{XHTTP_SC_MAX_BUFFERED_POSTS}")
        if XHTTP_XMUX_ENABLED:
            _box_row(f"  {CYAN}xmux:{NC}            включён (concurrency={XHTTP_XMUX_MAX_CONCURRENCY})")
        else:
            _box_row(f"  {CYAN}xmux:{NC}            отключён")
        _box_row(f"  {CYAN}tcpNoDelay:{NC}      {XHTTP_TCP_NO_DELAY}")
        _box_row(f"  {CYAN}SessionResumption:{NC}{XHTTP_ENABLE_SESSION_RESUMPTION}")
    _box_row(f"  {CYAN}Порт:{NC}            {SERVER_PORT}")
    _box_row(f"  {CYAN}UUID:{NC}            {PARAM_UUID}")
    _box_row(f"  {CYAN}ShortID:{NC}         {PARAM_SHORTID}")
    if PROTOCOL_MODE == "reality":
        if key_mode == "manual":
            _box_row(f"  {CYAN}Public Key:{NC}      {PARAM_PUBLIC_KEY}")
        else:
            _box_row(f"  {CYAN}Ключи:{NC}           (авто — после установки Xray)")
        _box_row(f"  {CYAN}SpiderX:{NC}         {PARAM_SPIDERX}")
        _box_row(f"  {CYAN}Socket:{NC}          {PARAM_SOCKET_PATH}")
    _box_row(f"  {CYAN}Домен:{NC}           {PARAM_DOMAIN}")
    _box_row(f"  {CYAN}Email (LE):{NC}      {PARAM_EMAIL}")
    _box_row(f"  {CYAN}Strategy:{NC}        {PARAM_DOMAIN_STRATEGY}")
    _box_row(f"  {CYAN}IPv6:{NC}            {IS_IPV6_AVAILABLE}")
    _box_row(f"  {CYAN}Шаблон:{NC}          {tmpl_names[int(PARAM_SITE_TEMPLATE)]}")
    dc_str = "да (зашифрованный DNS)" if PARAM_USE_DNSCRYPT else "нет (1.1.1.1 / 8.8.8.8)"
    _box_row(f"  {CYAN}DNSCrypt:{NC}        {dc_str}")
    _box_row()
    _box_bottom()

    try:
        ans = input(f"{YELLOW}Продолжить установку? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        print()
        raise
    if ans != 'y':
        info("Отменено — возврат в меню.")
        raise KeyboardInterrupt

    PRIVATE_KEY_MODE = key_mode
    setattr(core, "PRIVATE_KEY_MODE", PRIVATE_KEY_MODE)


# =============================================================================
#  ВЫБОР РЕЖИМА УСТАНОВКИ (A / B)
# =============================================================================
def prompt_install_mode() -> None:
    """Спросить пользователя: одиночный сервер (A) или каскадный прокси (B)."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_desc   = core._box_desc
    _box_bottom = core._box_bottom
    success = core.success
    warn    = core.warn
    BOLD   = core.BOLD
    CYAN   = core.CYAN
    YELLOW = core.YELLOW
    NC     = core.NC

    _box_top(f"Режим установки")
    _box_row()
    _box_item("A", f"🌐 Обычный сервер (Режим A)")
    _box_desc(f"Клиент → {BOLD}этот VPS{NC} → Интернет")
    _box_desc(f"Один сервер выполняет роль точки выхода.")
    _box_row()
    _box_item("B", f"🔗 Каскадный прокси (Режим B) — Chained")
    _box_desc(f"Клиент (RU) → {BOLD}этот VPS (RU){NC} → зарубежный VPS → Интернет")
    _box_desc(f"Используйте, если прямой коннект к зарубежному VPS нестабилен.")
    _box_desc(f"{YELLOW}Скрипт сгенерирует конфиги для ОБОИХ серверов.{NC}")
    _box_row()
    _box_bottom()
    while True:
        try:
            choice = input(f"  {CYAN}Выбор [A/B]:{NC} ").strip().upper()
        except KeyboardInterrupt:
            print()
            raise
        if choice in ('A', ''):
            INSTALL_MODE = "A"
            setattr(core, "INSTALL_MODE", INSTALL_MODE)
            success("Режим A: одиночный сервер")
            break
        elif choice == 'B':
            INSTALL_MODE = "B"
            setattr(core, "INSTALL_MODE", INSTALL_MODE)
            success("Режим B: каскадный прокси")
            break
        warn("Введите A или B")


def prompt_protocol_mode() -> None:
    """Выбор режима протокола: VLESS+TCP+REALITY или VLESS+xHTTP+TLS."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_desc   = core._box_desc
    _box_bottom = core._box_bottom
    success = core.success
    warn    = core.warn
    _prompt_xhttp_options = core._prompt_xhttp_options
    GREEN = core.GREEN
    CYAN  = core.CYAN
    NC    = core.NC

    _box_top(f"Режим протокола")
    _box_row()
    _box_item("1", f"🔒 VLESS + TCP + REALITY (xtls-rprx-vision) {GREEN}(рекомендуется){NC}")
    _box_desc(f"Максимальная производительность, аппаратное ускорение TLS.")
    _box_desc(f"Идеален как exit-нода и для прямых подключений.")
    _box_row()
    _box_item("2", f"🌐 VLESS + xHTTP + TLS")
    _box_desc(f"Трафик выглядит как обычный HTTPS-поток.")
    _box_desc(f"Обходит DPI через маскировку под HTTP/2 или chunked-streaming.")
    _box_row()
    _box_bottom()
    while True:
        try:
            choice = input(f"  {CYAN}Выбор [1/2]:{NC} ").strip() or "1"
        except KeyboardInterrupt:
            print()
            raise
        if choice == "1":
            PROTOCOL_MODE = "reality"
            setattr(core, "PROTOCOL_MODE", PROTOCOL_MODE)
            success("Протокол: VLESS + TCP + REALITY")
            break
        elif choice == "2":
            PROTOCOL_MODE = "xhttp"
            setattr(core, "PROTOCOL_MODE", PROTOCOL_MODE)
            _prompt_xhttp_options()
            break
        else:
            warn("Введите 1 или 2")

    # ── Выбор порта (общий для обоих протоколов) ─────────────────────────────
    _box_top(f"Порт прослушивания Xray")
    _box_row()
    _box_row()
    _box_item("1", f"443  {GREEN}(рекомендуется — стандартный HTTPS, меньше блокировок){NC}")
    _box_item("2", f"8443 (альтернатива, часто не блокируется)")
    _box_item("3", f"Ввести вручную (1–65535)")
    _box_bottom()
    while True:
        try:
            ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        except KeyboardInterrupt:
            print()
            raise
        if ch == "1":
            SERVER_PORT = 443
            setattr(core, "SERVER_PORT", SERVER_PORT)
            break
        elif ch == "2":
            SERVER_PORT = 8443
            setattr(core, "SERVER_PORT", SERVER_PORT)
            break
        elif ch == "3":
            while True:
                try:
                    raw = input("  Порт (1–65535): ").strip()
                except KeyboardInterrupt:
                    print()
                    raise
                if raw.isdigit() and 1 <= int(raw) <= 65535:
                    SERVER_PORT = int(raw)
                    setattr(core, "SERVER_PORT", SERVER_PORT)
                    break
                warn("  Введите число от 1 до 65535")
            break
        else:
            warn("Введите 1, 2 или 3")
    XHTTP_PORT = SERVER_PORT   # синхронизируем alias
    setattr(core, "XHTTP_PORT", XHTTP_PORT)
    print(f"  {GREEN}✓ Порт: {SERVER_PORT}{NC}")


# =============================================================================
#  ВЫБОР ТРАНСПОРТА EXIT-НОДЫ (VLESS / AWG / Hysteria2)
# =============================================================================

def _prompt_h1_h4_unique(
    _rec: dict,
    _ask_int_fn,
    warn_fn,
    info_fn,
) -> tuple:
    """Ввод H1-H4 с проверкой коллизий .

    Выделено в отдельную функцию для тестопригодности. Внутри
    prompt_awg_exit_mode() (ветка _obf_ch == "3") H1-H4 вводились через
    4 независимых _ask_int() вызова — дубликаты между ними никак не
    ловились, хотя весь смысл фичи — уникальность H1-H4 (DPI-отпечаток).

    Эта функция принимает:
      _rec:        dict с рекомендованными значениями (h1-h4 уникальны)
      _ask_int_fn: callback(prompt, default, lo, hi) -> int
      warn_fn:     callback(msg) для предупреждений
      info_fn:     callback(msg) для информационных сообщений

    Возвращает (h1, h2, h3, h4) — гарантированно уникальные значения.
    Если пользователь 5 раз подряд вводит дубликаты — fallback на _rec.
    """
    h1 = _ask_int_fn("Magic header H1 (1-2147483647)", _rec["h1"], 1, 2147483647)
    h2 = _ask_int_fn("Magic header H2 (1-2147483647)", _rec["h2"], 1, 2147483647)
    h3 = _ask_int_fn("Magic header H3 (1-2147483647)", _rec["h3"], 1, 2147483647)
    h4 = _ask_int_fn("Magic header H4 (1-2147483647)", _rec["h4"], 1, 2147483647)

    _h_vals = {"H1": h1, "H2": h2, "H3": h3, "H4": h4}
    _dupes = [k for k, v in _h_vals.items()
              if list(_h_vals.values()).count(v) > 1]
    _attempts = 0
    while _dupes:
        _attempts += 1
        if _attempts > 5:
            warn_fn("  5 попыток ввода H1-H4 с дубликатами — "
                    "использую рекомендованные уникальные значения")
            h1, h2, h3, h4 = _rec["h1"], _rec["h2"], _rec["h3"], _rec["h4"]
            break
        warn_fn(f"  H1-H4 не должны совпадать — обнаружен дубликат: "
                f"{', '.join(sorted(set(_dupes)))} = {_h_vals[_dupes[0]]}")
        info_fn("  Уникальность H1-H4 — то, что не даёт DPI написать "
                "универсальное правило для детекции. Введите ещё раз:")
        h1 = _ask_int_fn("Magic header H1 (1-2147483647)", _rec["h1"], 1, 2147483647)
        h2 = _ask_int_fn("Magic header H2 (1-2147483647)", _rec["h2"], 1, 2147483647)
        h3 = _ask_int_fn("Magic header H3 (1-2147483647)", _rec["h3"], 1, 2147483647)
        h4 = _ask_int_fn("Magic header H4 (1-2147483647)", _rec["h4"], 1, 2147483647)
        _h_vals = {"H1": h1, "H2": h2, "H3": h3, "H4": h4}
        _dupes = [k for k, v in _h_vals.items()
                  if list(_h_vals.values()).count(v) > 1]
    return h1, h2, h3, h4


def prompt_awg_exit_mode() -> None:
    """
    Спрашивает пользователя: использовать ли AWG как транспорт exit-ноды.
    Если да — запрашивает IP зарубежного VPS, параметры AWG и метод SSH-аутентификации.

    Решение проблемы фейковых VLESS-данных:
        Эта функция вызывается ДО prompt_chain_params_multi().
        do_full_install() затем проверяет AWG_EXIT_ENABLED:
            if not AWG_EXIT_ENABLED:
                prompt_chain_params_multi()
        При выборе AWG ввод VLESS-нод полностью пропускается.
    """
    core = _core_module()
    # ── Bind helpers ──────────────────────────────────────────────────────────
    #  FIX: добавлен _box_desc (забыли забиндить — NameError при показе
    # описаний вариантов обфускации AWG, строка 908+).
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    _box_desc   = core._box_desc
    _box_wrap_msg = core._box_wrap_msg
    success = core.success
    info    = core.info
    warn    = core.warn
    _prompt_awg_additional_nodes = core._prompt_awg_additional_nodes
    AWG_EXIT_PORT = core.AWG_EXIT_PORT
    AWG_JC        = core.AWG_JC
    AWG_JMIN      = core.AWG_JMIN
    AWG_JMAX      = core.AWG_JMAX
    AWG_S1        = core.AWG_S1
    AWG_S2        = core.AWG_S2
    AWG_H1        = core.AWG_H1
    AWG_H2        = core.AWG_H2
    AWG_H3        = core.AWG_H3
    AWG_H4        = core.AWG_H4
    AWG_MTU       = core.AWG_MTU
    # ── Bind colors ────────────────────────────────────────────────────────────
    BLUE   = core.BLUE
    CYAN   = core.CYAN
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    DIM    = core.DIM
    NC     = core.NC
    BOLD = core.BOLD

    print()
    _box_top("Транспорт для выхода в Интернет (Режим B)")
    _box_row()
    _box_wrap_msg(f"  {YELLOW}", 2,
        f"Выберите, как трафик Xray будет выходить в интернет с RU-сервера:{NC}")
    _box_row()
    _box_item("1", f"{GREEN}VLESS{NC}        — через цепочку VLESS-нод (классика, текущий режим)")
    _box_item("2", f"{CYAN}AmneziaWG 2.0{NC} — через AWG-туннель на зарубежный VPS (рекомендуется)")
    _box_item("3", f"{YELLOW}Hysteria2{NC}     — через QUIC/UDP туннель на зарубежный VPS")
    _box_row()
    _box_wrap_msg(f"  {DIM}", 2,
        f"AWG: устойчив к DPI, обфусцирован, не требует VLESS на exit-ноде.{NC}")
    _box_wrap_msg(f"  {DIM}", 2,
        f"H2: QUIC/UDP, высокая скорость, устойчив к потерям пакетов.{NC}")
    _box_bottom()

    while True:
        try:
            choice = input(f"  {CYAN}Выбор транспорта [1/2/3, Enter=1]:{NC} ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if choice in ("", "1"):
            AWG_EXIT_ENABLED = False
            setattr(core, "AWG_EXIT_ENABLED", AWG_EXIT_ENABLED)
            H2_EXIT_ENABLED  = False
            setattr(core, "H2_EXIT_ENABLED", H2_EXIT_ENABLED)
            success("Транспорт: VLESS (стандарт)")
            return
        if choice == "2":
            AWG_EXIT_ENABLED = True
            setattr(core, "AWG_EXIT_ENABLED", AWG_EXIT_ENABLED)
            H2_EXIT_ENABLED  = False
            setattr(core, "H2_EXIT_ENABLED", H2_EXIT_ENABLED)
            success("Транспорт: AmneziaWG 2.0")
            break
        if choice == "3":
            AWG_EXIT_ENABLED = False
            setattr(core, "AWG_EXIT_ENABLED", AWG_EXIT_ENABLED)
            H2_EXIT_ENABLED  = True
            setattr(core, "H2_EXIT_ENABLED", H2_EXIT_ENABLED)
            success("Транспорт: Hysteria2 (QUIC/UDP)")
            # H2 не требует ввода параметров здесь — настраивается через меню 7
            # после завершения установки. Ввод VLESS-нод пропускается.
            _box_top("Hysteria2 — информация")
            _box_row()
            _box_row(f"  {YELLOW}Hysteria2 выбран как транспорт exit-ноды.{NC}")
            _box_row()
            _box_row(f"  {DIM}Установка Xray (entry-нода) будет выполнена стандартным{NC}")
            _box_row(f"  {DIM}образом. После завершения установки:{NC}")
            _box_row()
            _box_row(f"  {CYAN}→{NC}  Перейдите в меню {BOLD}7 — Hysteria2 транспорт{NC}")
            _box_row(f"  {CYAN}→{NC}  Пункт {BOLD}1 — Exit-нода{NC}  (установка H2 на exit-VPS)")
            _box_row(f"  {CYAN}→{NC}  Пункт {BOLD}2 — Выбор транспорта{NC}  (активация H2)")
            _box_row()
            _box_bottom()
            input(f"  {CYAN}Нажмите Enter для продолжения установки...{NC}")
            return
        warn("Введите 1, 2 или 3")

    # --- Домен маскировки REALITY (dest/sni) ---
    _box_top("Домен маскировки REALITY (dest/sni)")
    _box_row()
    _box_wrap_msg(f"  {YELLOW}", 2,
        f"Укажите чужой популярный сайт с TLS 1.3 для маскировки.{NC}")
    _box_wrap_msg(f"  {DIM}", 2,
        f"Не используйте собственный домен — это создаст петлю маршрутизации.{NC}")
    _box_row()
    # ВНИМАНИЕ: www.microsoft.com НЕЛЬЗЯ использовать как REALITY dest!
    # Баг в TLS-парсере REALITY (xtls/reality, github.com/XTLS/Xray-core):
    # жёсткий лимит 8192 байта на TLS Certificate record. У www.microsoft.com
    # (Akamai CDN) Certificate с цепочкой/OCSP stapling сейчас 8273 байта —
    # на 81 байт больше лимита. REALITY обрывает разбор и валит соединение
    # с "handshake did not complete successfully" для ЛЮБОГО клиента.
    # Это НЕ связано с MTU/AWG — лимит внутри самого TLS-парсера REALITY,
    # до всякой маршрутизации. Прямой TLS к microsoft.com (curl/openssl)
    # при этом работает нормально.
    # Cloudflare использует ECDSA-сертификаты с минимальной цепочкой —
    # Certificate record гарантированно укладывается в 8192 байта.
    # Баг воспроизведён на Xray 26.3.27 (issue открыт ~2 недели назад).
    # Cloudflare исторически рекомендуемый target для REALITY — не только
    # из-за анонимности (слишком большой CDN, чтобы блокировать), но и из-за
    # предсказуемо маленького TLS-хендшейка.
    _box_wrap_msg(f"  {YELLOW}", 2,
        f"⚠️  ВНИМАНИЕ: НЕ используйте www.microsoft.com как REALITY dest!{NC}")
    _box_wrap_msg(f"  {DIM}", 2,
        f"Баг в TLS-парсере REALITY (Xray-core): лимит 8192 байт на "
        f"Certificate record, у microsoft.com — 8273 байта → handshake "
        f"падает для любого клиента. Cloudflare (ECDSA, компактная цепочка) "
        f"работает стабильно. Баг не связан с AWG/MTU — это лимит внутри "
        f"самого REALITY-парсера.{NC}")
    _box_row()
    try:
        _rd = input(f"  {CYAN}Домен маскировки REALITY [www.cloudflare.com]: {NC}").strip()
    except KeyboardInterrupt:
        print()
        raise
    # Дефолт — www.cloudflare.com (Certificate record укладывается в лимит REALITY).
    # Если пользователь явно ввёл microsoft.com — предупреждаем, но не блокируем.
    PARAM_REALITY_DEST = _rd if _rd else "www.cloudflare.com"
    if "microsoft.com" in PARAM_REALITY_DEST.lower():
        warn(f"  ⚠️  {PARAM_REALITY_DEST} НЕ рекомендуется: баг REALITY "
             f"(лимит 8192 байт на Certificate, у microsoft.com — 8273). "
             f"Handshake будет падать для всех клиентов. Рекомендуется "
             f"www.cloudflare.com.")
    setattr(core, "PARAM_REALITY_DEST", PARAM_REALITY_DEST)
    success(f"   REALITY dest/sni: {PARAM_REALITY_DEST}")

    # --- Ввод IP зарубежного VPS ---
    _box_top("Параметры AWG exit-ноды")
    _box_row()
    _box_wrap_msg(f"  {YELLOW}", 2,
        f"На зарубежном VPS будет автоматически установлен AWG-сервер.{NC}")
    _box_wrap_msg(f"  {YELLOW}", 2,
        f"Убедитесь, что у вас есть SSH-доступ к нему (root, по ключу).{NC}")
    _box_row()

    while True:
        try:
            host = input(f"  {CYAN}[A1] IP зарубежного VPS (для AWG-сервера):{NC} ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if host:
            AWG_EXIT_HOST = host
            setattr(core, "AWG_EXIT_HOST", AWG_EXIT_HOST)
            success(f"   AWG exit host: {AWG_EXIT_HOST}")
            break
        warn("IP не может быть пустым")

    _box_row(f"  {BLUE}[A2] UDP-порт AWG-сервера [{AWG_EXIT_PORT}]:{NC}")
    try:
        raw = input(f"  Enter для [{AWG_EXIT_PORT}]: ").strip()
        if raw.isdigit() and 1024 <= int(raw) <= 65535:
            AWG_EXIT_PORT = int(raw)
            setattr(core, "AWG_EXIT_PORT", AWG_EXIT_PORT)
    except (KeyboardInterrupt, ValueError):
        pass
    success(f"   AWG UDP-порт: {AWG_EXIT_PORT}")

    # --- Параметры обфускации (расширенный режим) ---
    _box_row()
    _box_row(f"  {YELLOW}Параметры обфускации AmneziaWG{NC}")
    _box_wrap_msg(f"  {DIM}", 2,
        f"Значения по умолчанию оптимальны для большинства случаев.{NC}")
    _box_row()
    #  3 варианта настройки обфускации — пресет / ручной ввод /
    # авто-полный набор. Раньше был только y/N на изменение дефолтов
    # (4/40/70/0/0/1/2/3/4) — без S3/S4/I1-I5, что ломало импорт в Keenetic.
    _box_item("1", f"{DIM}Использовать значения по умолчанию "
                    f"(Jc=4, Jmin=40, Jmax=70, S1-S4=0, H1-H4=1-4, без I1-I5){NC}")
    _box_desc("Старый режим — для обратной совместимости. НЕ рекомендуется "
              "для новых установок (нет I1, H1-H4 одинаковые у всех).")
    _box_item("2", f"{GREEN}Авто-генерация полного набора{NC} "
                    f"{DIM}(Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5 — случайно в "
                    f"рекомендованных диапазонах, H1-H4 уникальны){NC}")
    _box_desc("Рекомендуется. Уникальные H1-H4 — DPI не сможет написать "
              "универсальное правило. I1 генерируется для совместимости "
              "с Keenetic и другими строгими парсерами.")
    _box_item("3", f"{CYAN}Ввести параметры вручную{NC} "
                    f"{DIM}(с рекомендованными значениями){NC}")
    _box_desc("Полный контроль — каждый параметр вручную. Экспертный режим.")
    _box_item("4", f"{YELLOW}Готовый пресет под оператора{NC} "
                    f"{DIM}(Tele2, Yota, Мегафон, Билайн, T-Mobile US и др.){NC}")
    _box_desc("Carrier-специфичные значения, заточенные под конкретного "
              "оператора РФ/мира. 9 пресетов из bivlked/amneziawg-installer.")
    _box_row()

    try:
        _obf_ch = input(f"  {CYAN}Способ настройки [2 — рекомендуется]:{NC} ").strip()
    except KeyboardInterrupt:
        print()
        _obf_ch = "2"
    if _obf_ch not in ("1", "2", "3", "4"):
        _obf_ch = "2"  # default = авто-генерация

    if _obf_ch == "1":
        # Значения по умолчанию — ничего не меняем, AWG_OBFUSCATION_SOURCE = "default"
        setattr(core, "AWG_OBFUSCATION_SOURCE", "default")
        success("   Обфускация: значения по умолчанию (старый режим)")

    elif _obf_ch == "2":
        # Авто-генерация полного набора через awgs_generate_full_manual_params()
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        _p = awgs_generate_full_manual_params()  # без overrides = полный авто-рандом
        AWG_JC, AWG_JMIN, AWG_JMAX = _p["jc"], _p["jmin"], _p["jmax"]
        AWG_S1, AWG_S2, AWG_S3, AWG_S4 = _p["s1"], _p["s2"], _p["s3"], _p["s4"]
        AWG_H1, AWG_H2, AWG_H3, AWG_H4 = _p["h1"], _p["h2"], _p["h3"], _p["h4"]
        AWG_I1, AWG_I2, AWG_I3, AWG_I4, AWG_I5 = (
            _p["i1"], _p["i2"], _p["i3"], _p["i4"], _p["i5"]
        )
        for _k, _v in (
            ("AWG_JC", AWG_JC), ("AWG_JMIN", AWG_JMIN), ("AWG_JMAX", AWG_JMAX),
            ("AWG_S1", AWG_S1), ("AWG_S2", AWG_S2),
            ("AWG_S3", AWG_S3), ("AWG_S4", AWG_S4),
            ("AWG_H1", AWG_H1), ("AWG_H2", AWG_H2),
            ("AWG_H3", AWG_H3), ("AWG_H4", AWG_H4),
            ("AWG_I1", AWG_I1), ("AWG_I2", AWG_I2),
            ("AWG_I3", AWG_I3), ("AWG_I4", AWG_I4), ("AWG_I5", AWG_I5),
        ):
            setattr(core, _k, _v)
        setattr(core, "AWG_OBFUSCATION_SOURCE", "auto_full")
        success(f"   Обфускация: авто-генерация (полный набор, H1-H4 уникальны)")
        info(f"     Jc={AWG_JC} Jmin={AWG_JMIN} Jmax={AWG_JMAX}")
        info(f"     S1-S4={AWG_S1}/{AWG_S2}/{AWG_S3}/{AWG_S4}")
        info(f"     H1-H4={AWG_H1}/{AWG_H2}/{AWG_H3}/{AWG_H4}")
        if AWG_I1:
            info(f"     I1={AWG_I1[:32]}... (len={len(AWG_I1)})")

    elif _obf_ch == "3":
        # Ручной ввод полного набора — с рекомендованными значениями
        # Сначала генерируем рекомендации через awgs_generate_full_manual_params(),
        # затем предлагаем пользователю подтвердить или изменить каждый параметр.
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        _rec = awgs_generate_full_manual_params()

        def _ask_int(prompt: str, default: int, lo: int, hi: int) -> int:
            try:
                raw2 = input(f"  {prompt} [{default}]: ").strip()
                v = int(raw2)
                if lo <= v <= hi:
                    return v
            except (ValueError, KeyboardInterrupt):
                pass
            return default

        def _ask_hex(prompt: str, default: str) -> str:
            try:
                raw2 = input(f"  {prompt} [{default[:32]}{'...' if len(default) > 32 else ''}]: ").strip()
                if not raw2:
                    return default
                if raw2.lower() == "none":
                    return ""
                # v5.1: принимаем CPS tag-формат AWG 2.0 (<b 0x...>, <r N>,
                # <t>) и голый hex (AWG 1.5, для обратной совместимости).
                # См. awg_presets._is_valid_cps_or_legacy_hex для деталей.
                from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
                if _is_valid_cps_or_legacy_hex(raw2):
                    return raw2
                warn(f"  '{raw2[:32]}' не CPS tag и не hex — игнорирую, использую default")
            except (ValueError, KeyboardInterrupt):
                pass
            return default

        AWG_JC   = _ask_int("Junk packet count (Jc, 1-128)",   _rec["jc"],   1,   128)
        setattr(core, "AWG_JC",   AWG_JC)
        AWG_JMIN = _ask_int("Junk min size (Jmin, 0-1280)",    _rec["jmin"], 0,  1280)
        setattr(core, "AWG_JMIN", AWG_JMIN)
        AWG_JMAX = _ask_int("Junk max size (Jmax, 0-1280)",    _rec["jmax"], AWG_JMIN, 1280)
        setattr(core, "AWG_JMAX", AWG_JMAX)
        AWG_S1   = _ask_int("Init junk size S1 (0-1280)",      _rec["s1"],   0,  1280)
        setattr(core, "AWG_S1",   AWG_S1)
        AWG_S2   = _ask_int("Response junk size S2 (0-1280)",  _rec["s2"],   0,  1280)
        setattr(core, "AWG_S2",   AWG_S2)
        AWG_S3   = _ask_int("Under-load junk size S3 (0-64)",  _rec["s3"],   0,  64)
        setattr(core, "AWG_S3",   AWG_S3)
        AWG_S4   = _ask_int("Transport junk size S4 (0-32)",   _rec["s4"],   0,  32)
        setattr(core, "AWG_S4",   AWG_S4)
        AWG_H1, AWG_H2, AWG_H3, AWG_H4 = _prompt_h1_h4_unique(
            _rec, _ask_int, warn, info
        )
        setattr(core, "AWG_H1",   AWG_H1)
        setattr(core, "AWG_H2",   AWG_H2)
        setattr(core, "AWG_H3",   AWG_H3)
        setattr(core, "AWG_H4",   AWG_H4)
        # I1 — рекомендованный hex, можно 'none' чтобы пропустить
        AWG_I1   = _ask_hex("Init packet I1 (hex, или 'none')", _rec["i1"])
        setattr(core, "AWG_I1",   AWG_I1)
        # I2-I5 — по умолчанию пустые
        AWG_I2   = _ask_hex("Response packet I2 (hex, или 'none')", _rec["i2"])
        setattr(core, "AWG_I2",   AWG_I2)
        AWG_I3   = _ask_hex("Under-load packet I3 (hex, или 'none')", _rec["i3"])
        setattr(core, "AWG_I3",   AWG_I3)
        AWG_I4   = _ask_hex("Transport packet I4 (hex, или 'none')", _rec["i4"])
        setattr(core, "AWG_I4",   AWG_I4)
        AWG_I5   = _ask_hex("Transport IPv6 I5 (hex, или 'none')", _rec["i5"])
        setattr(core, "AWG_I5",   AWG_I5)
        AWG_MTU  = _ask_int("MTU интерфейса (1200-1420)",      AWG_MTU,  1200, 1420)
        setattr(core, "AWG_MTU",  AWG_MTU)
        setattr(core, "AWG_OBFUSCATION_SOURCE", "manual")
        success("   Обфускация: ручной ввод (полный набор)")

    elif _obf_ch == "4":
        # Готовый пресет оператора
        from chimera.modules.awg_presets import (
            awgs_presets_list, awgs_presets_get, awgs_presets_generate,
        )
        _presets = awgs_presets_list()
        _box_row()
        for i, _pname in enumerate(_presets, 1):
            _pinfo = awgs_presets_get(_pname)
            _box_row(f"  {CYAN}{i}{NC}) {_pname} — {_pinfo.get('label', '')}")
        _box_row()
        try:
            _pchoice = input(f"  {CYAN}Выберите пресет [1]:{NC} ").strip()
        except KeyboardInterrupt:
            _pchoice = "1"
        try:
            _pidx = int(_pchoice) - 1 if _pchoice else 0
        except ValueError:
            _pidx = 0
        if not (0 <= _pidx < len(_presets)):
            _pidx = 0
        _preset_name = _presets[_pidx]
        _p = awgs_presets_generate(_preset_name)
        AWG_JC, AWG_JMIN, AWG_JMAX = _p["jc"], _p["jmin"], _p["jmax"]
        AWG_S1, AWG_S2, AWG_S3, AWG_S4 = _p["s1"], _p["s2"], _p["s3"], _p["s4"]
        AWG_H1, AWG_H2, AWG_H3, AWG_H4 = _p["h1"], _p["h2"], _p["h3"], _p["h4"]
        AWG_I1, AWG_I2, AWG_I3, AWG_I4, AWG_I5 = (
            _p["i1"], _p["i2"], _p["i3"], _p["i4"], _p["i5"]
        )
        for _k, _v in (
            ("AWG_JC", AWG_JC), ("AWG_JMIN", AWG_JMIN), ("AWG_JMAX", AWG_JMAX),
            ("AWG_S1", AWG_S1), ("AWG_S2", AWG_S2),
            ("AWG_S3", AWG_S3), ("AWG_S4", AWG_S4),
            ("AWG_H1", AWG_H1), ("AWG_H2", AWG_H2),
            ("AWG_H3", AWG_H3), ("AWG_H4", AWG_H4),
            ("AWG_I1", AWG_I1), ("AWG_I2", AWG_I2),
            ("AWG_I3", AWG_I3), ("AWG_I4", AWG_I4), ("AWG_I5", AWG_I5),
        ):
            setattr(core, _k, _v)
        setattr(core, "AWG_OBFUSCATION_SOURCE", f"preset:{_preset_name}")
        success(f"   Обфускация: пресет '{_preset_name}'")
        info(f"     Jc={AWG_JC} Jmin={AWG_JMIN} Jmax={AWG_JMAX}")
        info(f"     H1-H4={AWG_H1}/{AWG_H2}/{AWG_H3}/{AWG_H4}")
        if AWG_I1:
            info(f"     I1={AWG_I1[:32]}... (len={len(AWG_I1)})")

    # --- Метод SSH-аутентификации для удалённой настройки exit-VPS ---
    _box_top("SSH-доступ к exit-VPS")
    _box_row()
    _box_wrap_msg(f"  {YELLOW}", 2,
        f"Скрипт подключится к {AWG_EXIT_HOST} по SSH для автонастройки AWG-сервера.{NC}")
    _box_row()
    _box_item("1", f"{GREEN}SSH-ключ{NC}  — использовать ~/.ssh/id_ed25519 / id_rsa (рекомендуется)")
    _box_item("2", f"{CYAN}Пароль{NC}    — ввести пароль root-пользователя")
    _box_row()

    while True:
        try:
            _ssh_ch = input(f"  {CYAN}Метод аутентификации [1/2, Enter=1]:{NC} ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if _ssh_ch in ("", "1"):
            AWG_SSH_AUTH_METHOD = "key"
            setattr(core, "AWG_SSH_AUTH_METHOD", AWG_SSH_AUTH_METHOD)
            success("   SSH-аутентификация: по ключу")
            break
        if _ssh_ch == "2":
            AWG_SSH_AUTH_METHOD = "password"
            setattr(core, "AWG_SSH_AUTH_METHOD", AWG_SSH_AUTH_METHOD)
            success("   SSH-аутентификация: по паролю")
            try:
                AWG_SSH_PASSWORD = getpass.getpass(
                    f"  Пароль для root@{AWG_EXIT_HOST}: "
                )
            except KeyboardInterrupt:
                print()
                AWG_SSH_AUTH_METHOD = "key"
                setattr(core, "AWG_SSH_AUTH_METHOD", AWG_SSH_AUTH_METHOD)
                AWG_SSH_PASSWORD    = ""
                setattr(core, "AWG_SSH_PASSWORD", AWG_SSH_PASSWORD)
                warn("Ввод пароля отменён — откат к SSH-ключу")
            else:
                setattr(core, "AWG_SSH_PASSWORD", AWG_SSH_PASSWORD)
            break
        warn("Введите 1 или 2")

    _box_row()
    _box_row(f"  AWG exit:      {AWG_EXIT_HOST}:{AWG_EXIT_PORT}/udp")
    _box_row(f"  SSH auth:      {AWG_SSH_AUTH_METHOD}")
    _box_row(f"  Jc/Jmin/Jmax:  {AWG_JC}/{AWG_JMIN}/{AWG_JMAX}")
    _box_row(f"  S1/S2:         {AWG_S1}/{AWG_S2}")
    _box_row(f"  H1-H4:         {AWG_H1}/{AWG_H2}/{AWG_H3}/{AWG_H4}")
    _box_row(f"  MTU:           {AWG_MTU}")
    _box_bottom()
    success("Параметры AWG сохранены")
    # === PATCH v2: спрашиваем о дополнительных нодах ===
    _prompt_awg_additional_nodes()
