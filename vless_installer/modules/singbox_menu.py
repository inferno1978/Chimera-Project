"""
vless_installer/modules/singbox_menu.py
───────────────────────────────────────────────────────────────────────────────
Главное меню «Sing-box (ShadowTLS / AnyTLS / TUIC)».

По образцу fptn.py / awg_standalone.py — отдельный пункт 17 в main_menu().

Подменю:
  1  Установить sing-box бинарник      (singbox_install.singbox_install_binary)
  2  ShadowTLS v3 + Trojan              (singbox_menu._shadowtls_menu)
  3  AnyTLS                              (singbox_menu._anytls_menu)
  4  TUIC v5                             (singbox_menu._tuic_menu)
  5  SNI-dispatch (nginx stream)         (singbox_menu._sni_dispatch_menu)
  6  Синхронизация users                 (singbox_users.singbox_sync_users)
  7  Старт/стоп/рестарт                  (singbox_install.singbox_restart)
  8  Статус                              (singbox_install.singbox_status)
  9  Логи                                (singbox_menu._show_logs)
  U  Удалить sing-box                    (singbox_install.singbox_uninstall_binary)
  0  ← Назад
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back, _box_desc, _box_info, _box_warn, _box_ok,
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, WHITE, NC,
)
from vless_installer.modules.singbox_common import (
    info, success, warn, error,
    _run, _singbox_binary_exists, _singbox_binary_version,
    _service_active, _service_enabled,
    _is_port_free, _who_owns_port,
    SINGBOX_BINARY, SINGBOX_CONFIG_FILE, SINGBOX_LOG_FILE,
    SINGBOX_SERVICE,
    SINGBOX_CERT_DIR,
    DEFAULT_PORT_SHADOWTLS, DEFAULT_PORT_ANYTLS,
    DEFAULT_SHADOWTLS_HANDSHAKE_HOST, DEFAULT_SHADOWTLS_HANDSHAKE_PORT,
    DEFAULT_PORT_TUIC_ALTERNATIVE,
    DEFAULT_PORT_VLESS_WS_CDN,
    CDN_PROVIDERS,
    LE_LIVE_DIR,
)
from vless_installer.modules.singbox_state import (
    singbox_state_load, singbox_state_save,
    singbox_state_is_installed, singbox_state_get_version,
    singbox_state_get_inbound, singbox_state_get_enabled_protocols,
    singbox_state_update_inbound,
)
from vless_installer.modules.singbox_install import (
    singbox_install_binary, singbox_uninstall_binary,
    singbox_start, singbox_stop, singbox_restart,
    singbox_status,
)
from vless_installer.modules.singbox_config import (
    singbox_generate_config, singbox_validate_config,
    singbox_enable_shadowtls, singbox_disable_shadowtls,
    singbox_enable_anytls, singbox_disable_anytls,
    singbox_enable_tuic, singbox_disable_tuic,
    singbox_enable_vless_ws_cdn, singbox_disable_vless_ws_cdn,
    _gen_random_ws_path,
)
from vless_installer.modules.singbox_users import (
    singbox_sync_users, singbox_get_users, singbox_state_list_users,
)
from vless_installer.modules.singbox_nginx import (
    enable_sni_dispatch, disable_sni_dispatch, sni_dispatch_status,
)
from vless_installer.modules.singbox_ufw import (
    singbox_ufw_ensure_open, singbox_ufw_close, singbox_ufw_close_all,
    singbox_ufw_status,
)
# v4.23.14: alias для удобства — loopback-проверка
def _is_loopback_listen_ip(ip: str) -> bool:
    return ip in ("127.0.0.1", "::1", "localhost")


def _disable_protocol_and_close_ufw(protocol: str) -> None:
    """Выключает протокол sing-box и закрывает его порт в UFW (v4.23.14).

    Общий путь для ShadowTLS / AnyTLS / TUIC / VLESS-WS-CDN.
    Читает state ДО выключения — чтобы знать listen/listen_port для close.
    """
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get(protocol, {})
    listen = ib.get("listen", "127.0.0.1")
    port = ib.get("listen_port", 0)
    proto_ufw = "udp" if protocol == "tuic" else "tcp"

    # Выключаем протокол
    if protocol == "shadowtls":
        singbox_disable_shadowtls()
    elif protocol == "anytls":
        singbox_disable_anytls()
    elif protocol == "tuic":
        singbox_disable_tuic()
    elif protocol == "vless_ws_cdn":
        singbox_disable_vless_ws_cdn()

    singbox_generate_config()
    if _service_active():
        singbox_restart()

    # Закрываем порт в UFW (только если был не-loopback)
    if port and not _is_loopback_listen_ip(listen):
        singbox_ufw_close(port, proto_ufw, protocol, listen=listen)


# ============================================================================
#  Шапка меню — единый формат
# ============================================================================
def _singbox_status_line() -> str:
    """Однострочный статус sing-box для шапки меню."""
    has_binary = _singbox_binary_exists()
    if not has_binary:
        return f"{YELLOW}не установлен{NC}"
    ver = _singbox_binary_version() or "?"
    active = _service_active()
    svc_col = GREEN if active else RED
    svc_str = f"{svc_col}{'активен' if active else 'DOWN'}{NC}"
    enabled_protocols = singbox_state_get_enabled_protocols()
    proto_col = CYAN if enabled_protocols else DIM
    proto_str = f"{proto_col}{','.join(enabled_protocols) if enabled_protocols else 'нет'}{NC}"
    return (
        f"v{ver}  │  Сервис: {svc_str}  │  "
        f"Протоколы: {proto_str}"
    )


# ============================================================================
#  Главное меню
# ============================================================================
def do_singbox_menu() -> None:
    """Главное меню sing-box. Вызывается из _core.py → main_menu() → пункт 17."""
    while True:
        os.system("clear")
        print()
        _box_top("📦  SING-BOX — SHADOWTLS / ANYTLS / TUIC")
        _box_row(f"  {_singbox_status_line()}")
        _box_sep()
        _box_desc(
            "Sing-box — параллельный backend для анти-цензурных протоколов. "
            "Работает независимо от Xray (REALITY), не затрагивает его конфигурацию. "
            "ShadowTLS v3 — маскировка под честный TLS-handshake. "
            "AnyTLS — новый TLS-camouflage протокол. "
            "TUIC v5 — QUIC-резерв к Hysteria2."
        )
        _box_sep()

        # ── Установка ──────────────────────────────────────────────────────
        _box_row()
        _box_item("1", f"📦 Установить sing-box          {DIM}скачать бинарник + systemd-unit{NC}")
        _box_row()
        _box_sep()

        # ── Протоколы ──────────────────────────────────────────────────────
        _box_row()
        _box_item("2", f"🎭 ShadowTLS v3 + Trojan        {DIM}маскировка под TLS-handshake к домену{NC}")
        _box_item("3", f"🔒 AnyTLS                       {DIM}новый TLS-camouflage протокол{NC}")
        _box_item("4", f"⚡ TUIC v5                      {DIM}QUIC-резерв к Hysteria2{NC}")
        _box_item("5", f"☁️  VLESS-WS-CDN                {DIM}VLESS+WS за Cloudflare/Gcore/Bunny{NC}  {DIM}(NEW){NC}")
        _box_row()
        _box_sep()

        # ── Диспетчеризация и пользователи ─────────────────────────────────
        _box_row()
        _box_item("6", f"🔀 SNI-dispatch                 {DIM}nginx stream{{}} + ssl_preread{NC}")
        _box_item("7", f"👥 Синхронизация users          {DIM}привязать unified users к sing-box{NC}")
        _box_row()
        _box_sep()

        # ── Управление сервисом ────────────────────────────────────────────
        _box_row()
        _box_item("8", f"🔄 Старт/стоп/рестарт           {DIM}управление systemd-юнитом{NC}")
        _box_item("9", f"📊 Статус                       {DIM}полная информация о состоянии{NC}")
        _box_item("L", f"📋 Логи                         {DIM}journalctl -u sing-box{NC}")
        _box_item("U", f"🗑️  Удалить sing-box             {DIM}сервис + бинарник + конфиг + state{NC}")
        _box_row()
        _box_item_exit("0", "← Назад в главное меню")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", ""):
            break

        elif ch == "1":
            singbox_install_binary()
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            _shadowtls_menu()
        elif ch == "3":
            _anytls_menu()
        elif ch == "4":
            _tuic_menu()
        elif ch == "5":
            _vless_ws_cdn_menu()
        elif ch == "6":
            _sni_dispatch_menu()
        elif ch == "7":
            _sync_users_menu()
        elif ch == "8":
            _service_menu()
        elif ch == "9":
            _show_status()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "L":
            _show_logs()
        elif ch == "U":
            _uninstall_menu()
        else:
            warn("Неверный выбор")
            time.sleep(0.8)


# ============================================================================
#  Общие хелперы для всех _enable_* / _regen_* / _change_* (v4.23.9)
# ============================================================================
def _apply_and_check(fail_msg: str = "sing-box не запустился") -> bool:
    """Рестарт/старт sing-box с проверкой результата.

    Если sing-box не стартует — печатает понятную ошибку и возвращает False,
    чтобы вызывающий код не печатал ложный success().

    Решает баг: _enable_*_default/custom() вызывали singbox_restart() без
    проверки return — даже при crash-loop пользователь видел «включено».
    """
    ok = singbox_restart() if _service_active() else singbox_start()
    if not ok:
        error(fail_msg)
        warn(f"Проверьте:  journalctl -u sing-box -n 50 --no-pager")
        warn(f"Конфиг:     {SINGBOX_CONFIG_FILE}")
        return False
    return True


def _prompt_alt_port(default_port: int, listen: str = "127.0.0.1",
                     proto: str = "tcp") -> int | None:
    """Если default_port занят — спрашивает альтернативу.

    Возвращает:
      • default_port, если он свободен
      • введённый пользователем порт, если он валиден и свободен
      • None, если пользователь отменил или ввёл невалидный порт
    """
    if _is_port_free(default_port, listen, proto=proto):
        return default_port

    who = _who_owns_port(default_port, listen, proto=proto)
    warn(f"Порт {default_port}/{proto} ({listen}) уже занят"
         + (f" {who}" if who else "") + ".")
    try:
        alt = input(
            f"{CYAN}Введите альтернативный порт {DIM}"
            f"(Enter — отмена):{NC} "
        ).strip()
    except KeyboardInterrupt:
        return None
    if not alt:
        info("Отменено")
        return None
    try:
        port = int(alt)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        error(f"Некорректный порт: {alt}")
        return None
    if port == default_port:
        error(f"Порт {port} занят (см. выше)")
        return None
    if not _is_port_free(port, listen, proto=proto):
        who2 = _who_owns_port(port, listen, proto=proto)
        error(f"Порт {port} тоже занят{(' ' + who2) if who2 else ''}")
        return None
    return port


def _is_valid_listen_ip(ip: str) -> bool:
    """True если строка — корректный listen-адрес.

    Принимает:
      • 0.0.0.0 (все IPv4)
      • :: (все IPv6)
      • конкретные IPv4/IPv6
      • 127.0.0.1, ::1, localhost
    """
    if not ip:
        return False
    if ip in ("0.0.0.0", "::", "localhost"):
        return True
    import socket as _socket
    try:
        _socket.inet_pton(_socket.AF_INET, ip)
        return True
    except OSError:
        pass
    try:
        _socket.inet_pton(_socket.AF_INET6, ip)
        return True
    except OSError:
        pass
    return False


def _change_listen_ip(protocol: str) -> None:
    """Смена listen-IP для уже включённого протокола (v4.23.13).

    Для ShadowTLS и AnyTLS — у них listen был жёстко 127.0.0.1 до v4.23.13.
    TUIC уже использует '::' по умолчанию, VLESS-WS-CDN — 0.0.0.0.
    """
    state = singbox_state_load()
    inbounds = state.get("inbounds", {})
    state_ib = inbounds.get(protocol, {})
    if not state_ib.get("enabled", False):
        warn(f"Протокол {protocol} не включён")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    cur_listen = state_ib.get("listen", "127.0.0.1")
    cur_port = state_ib.get("listen_port", 0)
    print()
    info(f"Текущий listen: {cur_listen}:{cur_port}")
    print(f"  {DIM}Варианты:{NC}")
    print(f"  {DIM}  127.0.0.1 — loopback (только SNI-dispatch/локально){NC}")
    print(f"  {DIM}  0.0.0.0   — все IPv4 (доступ извне, нужен firewall){NC}")
    print(f"  {DIM}  ::        — все IPv6{NC}")
    print(f"  {DIM}  <IP>      — конкретный интерфейс{NC}")
    try:
        new_listen = input(
            f"{CYAN}Новый Listen IP {DIM}(Enter — отмена):{NC} "
        ).strip()
    except KeyboardInterrupt:
        return
    if not new_listen:
        info("Отменено")
        return
    if not _is_valid_listen_ip(new_listen):
        error(f"Некорректный IP: {new_listen}")
        return
    if new_listen == cur_listen:
        info("Listen IP не изменился")
        return

    # Port-check на новом listen
    if cur_port and not _is_port_free(cur_port, new_listen, proto="tcp"):
        who = _who_owns_port(cur_port, new_listen, proto="tcp")
        error(f"Порт {cur_port} на {new_listen} занят"
              + (f" {who}" if who else ""))
        return

    if new_listen not in ("127.0.0.1", "::1", "localhost"):
        warn(f"⚠  {new_listen} — протокол будет доступен извне.")
        try:
            confirm = input(f"{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
        except KeyboardInterrupt:
            return
        if confirm != "y":
            info("Отменено")
            return

    # Обновляем state
    state_ib["listen"] = new_listen
    singbox_state_update_inbound(protocol, **state_ib)
    if not singbox_generate_config():
        return
    if not singbox_validate_config():
        warn("Конфиг невалиден")
        return
    if not _apply_and_check(f"Listen IP изменён, но sing-box не запустился"):
        return
    # v4.23.14: умное управление UFW
    # Если старый listen был не-loopback — закрыть старый порт.
    # Если новый listen не-loopback — открыть новый порт.
    proto_ufw = "udp" if protocol == "tuic" else "tcp"
    if not _is_loopback_listen_ip(cur_listen):
        singbox_ufw_close(cur_port, proto_ufw, protocol, listen=cur_listen)
    if not _is_loopback_listen_ip(new_listen):
        singbox_ufw_ensure_open(cur_port, proto_ufw, protocol, listen=new_listen)
    else:
        info("Listen loopback — порт в firewall не нужен (используйте SNI-dispatch)")
    success(f"Listen IP для {protocol}: {cur_listen} → {new_listen}")


# ============================================================================
#  Подменю: ShadowTLS v3
# ============================================================================
def _shadowtls_menu() -> None:
    while True:
        os.system("clear")
        print()
        state = singbox_state_load()
        ib = state.get("inbounds", {}).get("shadowtls", {})
        enabled = ib.get("enabled", False)
        col = GREEN if enabled else YELLOW
        listen = ib.get("listen", "127.0.0.1")
        port = ib.get("listen_port", DEFAULT_PORT_SHADOWTLS)
        handshake = ib.get("handshake", {})
        hs_server = handshake.get("server", DEFAULT_SHADOWTLS_HANDSHAKE_HOST)
        hs_port = handshake.get("server_port", DEFAULT_SHADOWTLS_HANDSHAKE_PORT)
        n_users = len(ib.get("users", []))

        _box_top("🎭  SHADOWTLS v3 + TROJAN")
        _box_row(f"  Статус:    {col}{'включён' if enabled else 'выключен'}{NC}")
        _box_row(f"  Listen:    {CYAN}{listen}:{port}{NC}  {DIM}(TCP){NC}")
        _box_row(f"  Handshake: {CYAN}{hs_server}:{hs_port}{NC}  {DIM}(маскировочный домен){NC}")
        _box_row(f"  Users:     {CYAN}{n_users}{NC}")
        _box_sep()
        _box_desc(
            "ShadowTLS v3 — зеркальный TLS-handshake: клиент устанавливает "
            "настоящий TLS к маскировочному домену, после handshake тихо "
            "переключается на внутренний Trojan. Активный зонд цензора "
            "получает честный TLS-ответ от маскировочного сайта. "
            "Локальный сертификат НЕ используется — протокол проксирует "
            "handshake на handshake.server."
        )
        _box_sep()
        _box_row()
        if enabled:
            _box_item("1", f"🔴 Выключить ShadowTLS")
            _box_item("2", f"🔑 Сменить пароль            {DIM}перегенерировать password{NC}")
            _box_item("3", f"🌐 Сменить handshake-домен    {DIM}маскировочный сайт{NC}")
            _box_item("4", f"👥 Показать пользователей     {DIM}список Trojan-users{NC}")
            _box_item("5", f"🔗 Клиентские ссылки          {DIM}URI + QR + JSON для импорта{NC}")
            _box_item("6", f"🖥  Сменить Listen IP          {DIM}127.0.0.1 ↔ 0.0.0.0{NC}")
        else:
            _box_item("1", f"🟢 Включить ShadowTLS         {DIM}с настройкой по умолчанию{NC}")
            _box_item("2", f"⚙️  Включить с custom-параметрами {DIM}домен/порт{NC}")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", ""):
            break

        if enabled:
            if ch == "1":
                _disable_protocol_and_close_ufw("shadowtls")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                _regen_password_shadowtls()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "3":
                _change_handshake_domain()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "4":
                _list_users_for_protocol("shadowtls")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "5":
                _show_client_links("shadowtls")
            elif ch == "6":
                _change_listen_ip("shadowtls")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
        else:
            if ch == "1":
                _enable_shadowtls_default()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                _enable_shadowtls_custom()
                input(f"\n{BLUE}Нажмите Enter...{NC}")


def _enable_shadowtls_default() -> None:
    """Включение ShadowTLS с дефолтными параметрами.

    v4.22.3: cert_path/key_path больше не передаются — ShadowTLS v3 не
    поддерживает локальный TLS-сертификат на inbound (см. _build_shadowtls_inbound).

    v4.23.9: pre-flight port-check — если дефолтный 8443 занят, предлагаем
    пользователю ввести альтернативу вместо crash-loop из 100+ рестартов.
    """
    if not _ensure_binary_installed():
        return

    # Pre-flight: дефолтный порт 8443 может быть занят (xray REALITY на loopback,
    # admin_panel.py, и т.д.). Спросим альтернативу ДО записи в state.
    listen_port = _prompt_alt_port(DEFAULT_PORT_SHADOWTLS, "127.0.0.1", "tcp")
    if listen_port is None:
        return

    ok = singbox_enable_shadowtls(listen_port=listen_port)
    if not ok:
        return
    # Синхронизируем users
    singbox_sync_users()
    if not singbox_generate_config():
        return
    if not singbox_validate_config():
        warn("Конфиг невалиден — проверьте логи")
        return
    if not _apply_and_check("ShadowTLS v3 + Trojan НЕ включены — sing-box не запустился"):
        return
    # v4.23.14: автоматически открыть порт в UFW (если активен)
    singbox_ufw_ensure_open(listen_port, "tcp", "shadowtls",
                            listen="127.0.0.1")  # default-режим — loopback
    success("ShadowTLS v3 + Trojan включены")


def _enable_shadowtls_custom() -> None:
    """Включение ShadowTLS с пользовательскими параметрами.

    v4.22.3: cert_path/key_path убраны — ShadowTLS v3 не поддерживает локальный
    TLS-сертификат. Custom-режим спрашивает только handshake-домен/порт и listen-порт.

    v4.23.9: listen-порт проверяется на занятость сразу после ввода.

    v4.23.13: добавлен запрос Listen IP — по умолчанию 127.0.0.1 (loopback),
    но можно указать 0.0.0.0 для прямой доступности извне.
    """
    if not _ensure_binary_installed():
        return
    try:
        hs_server = input(
            f"{CYAN}Handshake домен {DIM}(Enter={DEFAULT_SHADOWTLS_HANDSHAKE_HOST}):{NC} "
        ).strip() or DEFAULT_SHADOWTLS_HANDSHAKE_HOST
        hs_port_str = input(
            f"{CYAN}Handshake порт {DIM}(Enter=443):{NC} "
        ).strip()
        hs_port = int(hs_port_str) if hs_port_str else 443
        port_str = input(
            f"{CYAN}Listen порт {DIM}(Enter={DEFAULT_PORT_SHADOWTLS}):{NC} "
        ).strip()
        port = int(port_str) if port_str else DEFAULT_PORT_SHADOWTLS
        # v4.23.13: Listen IP — 127.0.0.1 (loopback) по умолчанию.
        # Для доступа извне — 0.0.0.0 (все IPv4) или конкретный IP.
        listen_ip = input(
            f"{CYAN}Listen IP {DIM}(Enter=127.0.0.1, варианты: 0.0.0.0=все IPv4, :: =все IPv6):{NC} "
        ).strip() or "127.0.0.1"
    except KeyboardInterrupt:
        info("Отменено")
        return
    except ValueError:
        error("Некорректный порт (должно быть число 1-65535)")
        return

    if not (1 <= port <= 65535):
        error(f"Listen порт вне диапазона: {port}")
        return
    # Валидация listen IP
    if not _is_valid_listen_ip(listen_ip):
        error(f"Некорректный Listen IP: {listen_ip}")
        warn("Допустимо: IP-адрес, 0.0.0.0 (все IPv4), :: (все IPv6), "
             "127.0.0.1 (loopback)")
        return
    if not _is_port_free(port, listen_ip, proto="tcp"):
        who = _who_owns_port(port, listen_ip, proto="tcp")
        error(f"Listen порт {port} на {listen_ip} уже занят"
              + (f" {who}" if who else ""))
        warn("Выберите другой порт (ss -ltnp | grep ':<port> ')")
        return

    if listen_ip not in ("127.0.0.1", "::1", "localhost"):
        warn(f"⚠  Listen IP = {listen_ip} — ShadowTLS будет доступен извне.")
        warn("Цензор сможет напрямую зондировать порт. Для скрытности")
        warn("рекомендуется SNI-dispatch (меню 5) на loopback-бэкенде.")
        try:
            confirm = input(f"{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
        except KeyboardInterrupt:
            return
        if confirm != "y":
            info("Отменено")
            return

    ok = singbox_enable_shadowtls(
        handshake_server=hs_server,
        handshake_port=hs_port,
        listen_port=port,
        listen=listen_ip,
    )
    if not ok:
        return
    singbox_sync_users()
    if not singbox_generate_config():
        return
    if not singbox_validate_config():
        warn("Конфиг невалиден")
        return
    if not _apply_and_check("ShadowTLS v3 НЕ включён — sing-box не запустился"):
        return
    # v4.23.14: автоматически открыть порт в UFW (если активен и не loopback)
    singbox_ufw_ensure_open(port, "tcp", "shadowtls", listen=listen_ip)
    success("ShadowTLS v3 включён с custom-параметрами")
    if listen_ip in ("127.0.0.1", "::1", "localhost"):
        info("Listen loopback — порт в firewall не открывается (используйте SNI-dispatch)")


def _regen_password_shadowtls() -> None:
    from vless_installer.modules.singbox_users import singbox_gen_password
    new_pw = singbox_gen_password()
    singbox_state_update_inbound("shadowtls", password=new_pw)
    # Обновляем пароль у всех users в ShadowTLS и Trojan
    state = singbox_state_load()
    for proto in ("shadowtls", "trojan"):
        ib = state.get("inbounds", {}).get(proto, {})
        users = ib.get("users", [])
        for u in users:
            u["password"] = new_pw
        singbox_state_update_inbound(proto, users=users, password=new_pw)
    singbox_generate_config()
    if not _apply_and_check("Пароль обновлён, но sing-box не запустился"):
        return
    success("Пароль ShadowTLS/Trojan перегенерирован")
    warn("ВНИМАНИЕ: клиентам нужно раздать новые ссылки/пароли!")


def _change_handshake_domain() -> None:
    try:
        new_host = input(
            f"{CYAN}Новый handshake домен{NC} "
            f"{DIM}(Enter={DEFAULT_SHADOWTLS_HANDSHAKE_HOST}):{NC} "
        ).strip() or DEFAULT_SHADOWTLS_HANDSHAKE_HOST
        new_port_str = input(f"{CYAN}Порт {DIM}(Enter=443):{NC} ").strip()
        new_port = int(new_port_str) if new_port_str else 443
    except KeyboardInterrupt:
        return
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("shadowtls", {})
    ib.setdefault("handshake", {})
    ib["handshake"] = {"server": new_host, "server_port": new_port}
    singbox_state_update_inbound("shadowtls", **ib)
    singbox_generate_config()
    if not _apply_and_check("Handshake изменён, но sing-box не запустился"):
        return
    success(f"Handshake: {new_host}:{new_port}")


def _configure_tuic_initial_packet_size() -> None:
    """Настройка initial_packet_size для TUIC v5 (v4.22.4).

    ВАЖНО: это НЕ замена obfs (salamander/gecko) — TUIC не поддерживает obfs
    в схеме sing-box вообще. initial_packet_size — общее поле QUIC Fields,
    регулирует размер начального QUIC-пакета. Это частичный митигейт против
    DPI, классифицирующего по длине initial-packet: меняет размер, но не
    шифрует содержимое. Для полной обфускации QUIC используйте Hysteria2 +
    Salamander (меню 7 → O).
    """
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("tuic", {})
    current = ib.get("initial_packet_size")

    print()
    _box_top("📦  INITIAL_PACKET_SIZE ДЛЯ TUIC v5")
    _box_row(f"  Текущее: {CYAN}{current if current is not None else 'не задан (sing-box default)'}{NC}")
    _box_sep()
    _box_desc(
        "initial_packet_size — размер начального QUIC-пакета в байтах. "
        "Прямой рычаг против DPI, классифицирующего по длине initial-packet. "
        "Рекомендуемый диапазон: 1200-1400 (MTU-safe). 0 = sing-box default."
    )
    _box_sep()
    _box_warn("Это НЕ obfs и НЕ обфускация трафика. TUIC не поддерживает")
    _box_warn("salamander/gecko — это поле схемы только для Hysteria/Hysteria2.")
    _box_warn("initial_packet_size меняет только размер пакета, не шифруя")
    _box_warn("содержимое. Для полной обфускации QUIC используйте Hysteria2")
    _box_warn("с Salamander (меню 7 → O).")
    _box_bottom()

    print()
    info("Введите новое значение initial_packet_size (в байтах).")
    info("  Рекомендуемый диапазон: 1200-1400")
    info("  0 или пустой ввод — сбросить к sing-box default (поле убирается из конфига)")
    try:
        raw = input(f"{CYAN}initial_packet_size:{NC} ").strip()
    except KeyboardInterrupt:
        return

    if not raw or raw == "0":
        # Сброс — убираем поле из state
        ib.pop("initial_packet_size", None)
        singbox_state_update_inbound("tuic", **ib)
        singbox_generate_config()
        if not _apply_and_check("initial_packet_size сброшен, но sing-box не запустился"):
            return
        success("initial_packet_size сброшен к sing-box default")
        return

    try:
        value = int(raw)
    except ValueError:
        warn("Некорректное значение — ожидается целое число")
        time.sleep(1.5)
        return

    if value < 0:
        warn("Значение должно быть >= 0")
        time.sleep(1.5)
        return

    if value > 0 and value < 100:
        warn("Очень маленькое значение (< 100) — может сломать QUIC handshake")
        try:
            confirm = input(f"{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
        except KeyboardInterrupt:
            return
        if confirm != "y":
            return

    ib["initial_packet_size"] = value
    singbox_state_update_inbound("tuic", **ib)
    singbox_generate_config()
    if not _apply_and_check(f"initial_packet_size установлен, но sing-box не запустился"):
        return
    success(f"initial_packet_size = {value} байт")


# _change_cert_shadowtls() удалён в v4.22.3 — ShadowTLS v3 не поддерживает
# локальный TLS-сертификат на inbound (протокол проксирует handshake на
# handshake.server, наблюдатель видит настоящий сертификат реального сайта).
# Поля cert_path/key_path/cert_source в state игнорируются генератором конфига.
# См. _build_shadowtls_inbound() docstring.


# ============================================================================
#  Подменю: AnyTLS
# ============================================================================
def _anytls_menu() -> None:
    while True:
        os.system("clear")
        print()
        state = singbox_state_load()
        ib = state.get("inbounds", {}).get("anytls", {})
        enabled = ib.get("enabled", False)
        col = GREEN if enabled else YELLOW
        listen = ib.get("listen", "127.0.0.1")
        port = ib.get("listen_port", DEFAULT_PORT_ANYTLS)
        cert_path = ib.get("cert_path", "")
        cert_src = ib.get("cert_source", "(не задан)")
        n_users = len(ib.get("users", []))

        _box_top("🔒  ANYTLS")
        _box_row(f"  Статус:  {col}{'включён' if enabled else 'выключен'}{NC}")
        _box_row(f"  Listen:  {CYAN}{listen}:{port}{NC}  {DIM}(TCP){NC}")
        _box_row(f"  Cert:    {DIM}{cert_src}{NC}")
        if cert_path:
            _box_row(f"           {DIM}{cert_path}{NC}")
        _box_row(f"  Users:   {CYAN}{n_users}{NC}")
        _box_sep()
        _box_desc(
            "AnyTLS — новый протокол (2024). Скрывает внутренний трафик за "
            "TLS-сессией к своему домену с настоящим сертификатом. В отличие "
            "от REALITY не требует «чужого» сайта — поднимается на своём. "
            "Активные пробы видят честный TLS."
        )
        _box_sep()
        _box_row()
        if enabled:
            _box_item("1", f"🔴 Выключить AnyTLS")
            _box_item("2", f"🔑 Сменить пароль")
            _box_item("3", f"👥 Показать пользователей")
            _box_item("4", f"🔗 Клиентские ссылки          {DIM}URI + QR + JSON{NC}")
            _box_item("5", f"🖥  Сменить Listen IP          {DIM}127.0.0.1 ↔ 0.0.0.0{NC}")
        else:
            _box_item("1", f"🟢 Включить AnyTLS  {DIM}с self-signed cert{NC}")
            _box_item("2", f"⚙️  Включить с custom-параметрами {DIM}порт/IP{NC}")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", ""):
            break

        if enabled:
            if ch == "1":
                _disable_protocol_and_close_ufw("anytls")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                _regen_password("anytls")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "3":
                _list_users_for_protocol("anytls")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "4":
                _show_client_links("anytls")
            elif ch == "5":
                _change_listen_ip("anytls")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
        else:
            if ch == "1":
                _enable_anytls_default()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                _enable_anytls_custom()
                input(f"\n{BLUE}Нажмите Enter...{NC}")


def _enable_anytls_default() -> None:
    """Включение AnyTLS с дефолтными параметрами (v4.23.19 вынесено из меню).

    v4.23.18: pre-flight port-check — если дефолтный 8444 занят, предлагаем
    альтернативу вместо crash-loop.
    """
    if not _ensure_binary_installed():
        return
    # Pre-flight: дефолтный порт 8444 может быть занят nginx (SNI-dispatch backend)
    listen_port = _prompt_alt_port(DEFAULT_PORT_ANYTLS, "127.0.0.1", "tcp")
    if listen_port is None:
        return
    # common_name = домен сервера (для auto-detect SNI)
    import json as _json
    from vless_installer.modules.singbox_common import MAIN_STATE_FILE
    try:
        _ms = _json.loads(MAIN_STATE_FILE.read_text()) if MAIN_STATE_FILE.exists() else {}
        server_domain = _ms.get("domain", "")
    except Exception:
        server_domain = ""
    cert_path, key_path, cn = _ensure_self_signed_cert("anytls", common_name=server_domain)
    ok = singbox_enable_anytls(
        cert_path=str(cert_path),
        key_path=str(key_path),
        cert_source="self-signed",
        common_name=cn,
        listen_port=listen_port,
    )
    if not ok:
        return
    singbox_sync_users()
    if not singbox_generate_config():
        return
    if not singbox_validate_config():
        warn("Конфиг невалиден — проверьте логи")
        return
    if not _apply_and_check("AnyTLS НЕ включён — sing-box не запустился"):
        return
    # UFW для AnyTLS (loopback по умолчанию)
    singbox_ufw_ensure_open(listen_port, "tcp", "anytls", listen="127.0.0.1")
    success("AnyTLS включён")


def _enable_anytls_custom() -> None:
    """Включение AnyTLS с пользовательскими параметрами (v4.23.19).

    Запрашивает:
      • Listen порт (с pre-flight проверкой занятости)
      • Listen IP (127.0.0.1 loopback или 0.0.0.0 извне)
      • Common name для self-signed cert (для SNI)

    По образцу _enable_shadowtls_custom().
    """
    if not _ensure_binary_installed():
        return
    try:
        port_str = input(
            f"{CYAN}Listen порт {DIM}(Enter={DEFAULT_PORT_ANYTLS}):{NC} "
        ).strip()
        port = int(port_str) if port_str else DEFAULT_PORT_ANYTLS
        listen_ip = input(
            f"{CYAN}Listen IP {DIM}(Enter=127.0.0.1, варианты: 0.0.0.0=все IPv4, :: =все IPv6):{NC} "
        ).strip() or "127.0.0.1"
        # Common name для self-signed cert (для SNI)
        cn_input = input(
            f"{CYAN}Common Name (SNI) {DIM}(Enter=домен сервера из state):{NC} "
        ).strip()
    except KeyboardInterrupt:
        info("Отменено")
        return
    except ValueError:
        error("Некорректный порт (должно быть число 1-65535)")
        return

    if not (1 <= port <= 65535):
        error(f"Listen порт вне диапазона: {port}")
        return
    if not _is_valid_listen_ip(listen_ip):
        error(f"Некорректный Listen IP: {listen_ip}")
        warn("Допустимо: IP-адрес, 0.0.0.0 (все IPv4), :: (все IPv6), 127.0.0.1 (loopback)")
        return
    if not _is_port_free(port, listen_ip, proto="tcp"):
        who = _who_owns_port(port, listen_ip, proto="tcp")
        error(f"Listen порт {port} на {listen_ip} уже занят" + (f" {who}" if who else ""))
        warn("Выберите другой порт (ss -ltnp | grep ':<port> ')")
        return

    if listen_ip not in ("127.0.0.1", "::1", "localhost"):
        warn(f"⚠  Listen IP = {listen_ip} — AnyTLS будет доступен извне.")
        warn("Цензор сможет напрямую зондировать порт. Для скрытности")
        warn("рекомендуется SNI-dispatch (меню 5) на loopback-бэкенде.")
        try:
            confirm = input(f"{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
        except KeyboardInterrupt:
            return
        if confirm != "y":
            info("Отменено")
            return

    # Common name: если пользователь не указал — берём из основного state
    if cn_input:
        common_name = cn_input
    else:
        import json as _json
        from vless_installer.modules.singbox_common import MAIN_STATE_FILE
        try:
            _ms = _json.loads(MAIN_STATE_FILE.read_text()) if MAIN_STATE_FILE.exists() else {}
            common_name = _ms.get("domain", "")
        except Exception:
            common_name = ""

    cert_path, key_path, cn = _ensure_self_signed_cert("anytls", common_name=common_name)
    ok = singbox_enable_anytls(
        cert_path=str(cert_path),
        key_path=str(key_path),
        cert_source="self-signed",
        common_name=cn,
        listen_port=port,
        listen=listen_ip,
    )
    if not ok:
        return
    singbox_sync_users()
    if not singbox_generate_config():
        return
    if not singbox_validate_config():
        warn("Конфиг невалиден")
        return
    if not _apply_and_check("AnyTLS НЕ включён — sing-box не запустился"):
        return
    # v4.23.14: UFW для AnyTLS
    singbox_ufw_ensure_open(port, "tcp", "anytls", listen=listen_ip)
    success("AnyTLS включён с custom-параметрами")
    if listen_ip in ("127.0.0.1", "::1", "localhost"):
        info("Listen loopback — порт в firewall не открывается (используйте SNI-dispatch)")
    else:
        info(f"Не забудьте: порт {port}/tcp открыт в UFW автоматически (если UFW активен)")


# ============================================================================
#  Подменю: TUIC v5
# ============================================================================
def _tuic_menu() -> None:
    while True:
        os.system("clear")
        print()
        state = singbox_state_load()
        ib = state.get("inbounds", {}).get("tuic", {})
        enabled = ib.get("enabled", False)
        col = GREEN if enabled else YELLOW
        listen = ib.get("listen", "::")
        port = ib.get("listen_port", DEFAULT_PORT_TUIC_ALTERNATIVE)
        cc = ib.get("congestion_control", "bbr")
        cert_path = ib.get("cert_path", "")
        cert_src = ib.get("cert_source", "(не задан)")
        ips = ib.get("initial_packet_size")
        ips_str = f"{CYAN}{ips}{NC}" if ips is not None else f"{DIM}не задан (sing-box default){NC}"
        n_users = len(ib.get("users", []))

        _box_top("⚡  TUIC v5")
        _box_row(f"  Статус:    {col}{'включён' if enabled else 'выключен'}{NC}")
        _box_row(f"  Listen:    {CYAN}{listen}:{port}{NC}  {DIM}(UDP, не конфликтует с TCP:443){NC}")
        _box_row(f"  CongCtrl:  {CYAN}{cc}{NC}")
        _box_row(f"  InitPkt:   {ips_str}  {DIM}(QUIC initial-packet size){NC}")
        _box_row(f"  Cert:      {DIM}{cert_src}{NC}")
        if cert_path:
            _box_row(f"             {DIM}{cert_path}{NC}")
        _box_row(f"  Users:     {CYAN}{n_users}{NC}")
        _box_sep()
        _box_desc(
            "TUIC v5 — QUIC-протокол, резерв к Hysteria2. Другой fingerprint, "
            "другая congestion control (BBRv2 native), нативный UDP-relay без "
            "Hysteria-специфичных 'brutal'. ВАЖНО: TUIC не поддерживает obfs "
            "(salamander/gecko) — это поле схемы только для Hysteria/Hysteria2. "
            "Единственный доступный рычаг против DPI по длине initial-packet — "
            "initial_packet_size (пункт 4). Это НЕ обфускация, а частичный "
            "митигейт: меняет размер пакета, но не шифрует содержимое."
        )
        _box_sep()
        _box_row()
        if enabled:
            _box_item("1", f"🔴 Выключить TUIC")
            _box_item("2", f"🔑 Перегенерировать пароли пользователей")
            _box_item("3", f"👥 Показать пользователей")
            _box_item("4", f"📦 Настроить initial_packet_size  {DIM}частичный DPI-митигейт{NC}")
            _box_item("5", f"🔗 Клиентские ссылки            {DIM}URI + QR + JSON{NC}")
        else:
            _box_item("1", f"🟢 Включить TUIC v5  {DIM}с self-signed cert{NC}")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", ""):
            break

        if enabled:
            if ch == "1":
                _disable_protocol_and_close_ufw("tuic")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                _regen_password("tuic")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "3":
                _list_users_for_protocol("tuic")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "4":
                _configure_tuic_initial_packet_size()
            elif ch == "5":
                _show_client_links("tuic")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
        else:
            if ch == "1":
                if not _ensure_binary_installed():
                    continue
                cert_path, key_path, _ = _ensure_self_signed_cert("tuic")
                ok = singbox_enable_tuic(
                    cert_path=str(cert_path),
                    key_path=str(key_path),
                    cert_source="self-signed",
                )
                if ok:
                    singbox_sync_users()
                    singbox_generate_config()
                    if singbox_validate_config():
                        if not _apply_and_check("TUIC v5 НЕ включён — sing-box не запустился"):
                            pass
                        else:
                            # v4.23.14: UFW для TUIC (UDP, listen=::)
                            singbox_ufw_ensure_open(
                                DEFAULT_PORT_TUIC_ALTERNATIVE, "udp", "tuic",
                                listen="::")
                            success("TUIC v5 включён")
                input(f"\n{BLUE}Нажмите Enter...{NC}")


# ============================================================================
#  Подменю: VLESS-WS-CDN (v4.23)
# ============================================================================
def _vless_ws_cdn_menu() -> None:
    while True:
        os.system("clear")
        print()
        state = singbox_state_load()
        ib = state.get("inbounds", {}).get("vless_ws_cdn", {})
        enabled = ib.get("enabled", False)
        col = GREEN if enabled else YELLOW
        listen = ib.get("listen", "0.0.0.0")
        port = ib.get("listen_port", DEFAULT_PORT_VLESS_WS_CDN)
        host = ib.get("host", "")
        ws_path = ib.get("ws_path", "")
        uuid_val = ib.get("uuid", "")
        cdn_provider = ib.get("cdn_provider", "")
        cdn_display = CDN_PROVIDERS.get(cdn_provider, {}).get("display_name", "(не задан)")

        _box_top("☁️   VLESS-WS-CDN")
        _box_row(f"  Статус:       {col}{'включён' if enabled else 'выключен'}{NC}")
        _box_row(f"  Listen:       {CYAN}{listen}:{port}{NC}  {DIM}(TCP, externally bound){NC}")
        _box_row(f"  CDN Provider: {CYAN}{cdn_display}{NC}")
        _box_row(f"  Host:         {CYAN}{host or '—'}{NC}")
        _box_row(f"  WS Path:      {CYAN}{ws_path or '—'}{NC}")
        if uuid_val:
            _box_row(f"  UUID:         {DIM}{uuid_val}{NC}")
        _box_sep()
        _box_desc(
            "VLESS+WebSocket за CDN (Cloudflare/Gcore/Bunny). CDN терминирует "
            "TLS своим сертификатом, origin (sing-box) слушает plain WS. "
            "Цензор видит TLS к CDN IP — заблокировать = заблокировать весь CDN. "
            "Локальный сертификат НЕ нужен и НЕ используется."
        )
        _box_sep()
        _box_row()
        if enabled:
            _box_item("1", f"🔴 Выключить VLESS-WS-CDN")
            _box_item("2", f"🔄 Сменить CDN-провайдера       {DIM}cloudflare/gcore/bunny{NC}")
            _box_item("3", f"🌐 Сменить Host                 {DIM}домен через CDN{NC}")
            _box_item("4", f"🔑 Перегенерировать WS path     {DIM}новый случайный path{NC}")
            _box_item("5", f"🔑 Перегенерировать UUID        {DIM}новый клиентский UUID{NC}")
            _box_item("6", f"📖 Показать инструкцию CDN      {DIM}что настроить в панели{NC}")
            _box_item("7", f"🔗 Клиентские ссылки            {DIM}vless:// URI + QR + JSON{NC}")
        else:
            _box_item("1", f"🟢 Включить VLESS-WS-CDN        {DIM}с настройкой по умолчанию{NC}")
            _box_item("2", f"⚙️  Включить с custom-параметрами {DIM}provider/host/path{NC}")
            _box_item("6", f"📖 Показать инструкцию CDN      {DIM}до включения — что настроить{NC}")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", ""):
            break

        if enabled:
            if ch == "1":
                _disable_protocol_and_close_ufw("vless_ws_cdn")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                _switch_cdn_provider()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "3":
                _change_vless_ws_cdn_host()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "4":
                _regen_vless_ws_cdn_path()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "5":
                _regen_vless_ws_cdn_uuid()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "6":
                _show_cdn_instructions(cdn_provider)
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "7":
                _show_client_links("vless_ws_cdn")
        else:
            if ch == "1":
                _enable_vless_ws_cdn_default()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                _enable_vless_ws_cdn_custom()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "6":
                # Если провайдер не выбран — покажем выбор
                provider = _pick_cdn_provider()
                if provider:
                    _show_cdn_instructions(provider)
                input(f"\n{BLUE}Нажмите Enter...{NC}")


def _enable_vless_ws_cdn_default() -> None:
    """Включение с дефолтами: Cloudflare, random WS path, random UUID."""
    if not _ensure_binary_installed():
        return
    # Спросим Host — это обязательный параметр (домен через CDN)
    try:
        host = input(
            f"{CYAN}Host (домен через CDN, напр. vless.example.com):{NC} "
        ).strip()
    except KeyboardInterrupt:
        return
    if not host:
        warn("Host обязателен — без него CDN не будет знать куда направлять Host header")
        time.sleep(1.5)
        return

    ok = singbox_enable_vless_ws_cdn(
        cdn_provider="cloudflare",
        host=host,
    )
    if not ok:
        return
    if not singbox_generate_config():
        return
    if not singbox_validate_config():
        warn("Конфиг невалиден — проверьте логи")
        return
    if not _apply_and_check("VLESS-WS-CDN НЕ включён — sing-box не запустился"):
        return
    # v4.23.14: UFW для VLESS-WS-CDN (listen=0.0.0.0 по умолчанию)
    singbox_ufw_ensure_open(
        DEFAULT_PORT_VLESS_WS_CDN, "tcp", "vless_ws_cdn", listen="0.0.0.0")
    success("VLESS-WS-CDN включён (Cloudflare)")
    _show_cdn_instructions("cloudflare")


def _enable_vless_ws_cdn_custom() -> None:
    """Включение с custom-параметрами."""
    if not _ensure_binary_installed():
        return
    provider = _pick_cdn_provider()
    if not provider:
        return
    try:
        host = input(
            f"{CYAN}Host (домен через CDN):{NC} "
        ).strip()
        ws_path_in = input(
            f"{CYAN}WS Path {DIM}(Enter = случайный):{NC} "
        ).strip()
        port_in = input(
            f"{CYAN}Listen порт {DIM}(Enter={DEFAULT_PORT_VLESS_WS_CDN}):{NC} "
        ).strip()
    except KeyboardInterrupt:
        return
    if not host:
        warn("Host обязателен")
        time.sleep(1.5)
        return
    listen_port = 0
    if port_in:
        try:
            listen_port = int(port_in)
        except ValueError:
            warn("Некорректный порт")
            time.sleep(1.5)
            return

    ok = singbox_enable_vless_ws_cdn(
        cdn_provider=provider,
        host=host,
        ws_path=ws_path_in if ws_path_in else "",
        listen_port=listen_port,
    )
    if not ok:
        return
    if not singbox_generate_config():
        return
    if not singbox_validate_config():
        warn("Конфиг невалиден")
        return
    if not _apply_and_check("VLESS-WS-CDN НЕ включён — sing-box не запустился"):
        return
    # v4.23.14: UFW для VLESS-WS-CDN (listen=0.0.0.0)
    singbox_ufw_ensure_open(
        listen_port, "tcp", "vless_ws_cdn", listen="0.0.0.0")
    success(f"VLESS-WS-CDN включён ({CDN_PROVIDERS[provider]['display_name']})")
    _show_cdn_instructions(provider)


def _switch_cdn_provider() -> None:
    """Переключение CDN-провайдера без потери uuid/ws_path/host (manual switch).

    v4.23.1: allowlist переприменяется под новый провайдер.
    v4.23.2: авто-смена listen_port если текущий = дефолтный порт СТАРОГО провайдера.
             Если порт был custom (не равен дефолту старого) — порт НЕ трогаем,
             но warn() о возможной невалидности.
    v4.23.3: allowlist применяется ДО generate_config/restart — НЕ оставляем
             окно с открытым портом без защиты. Старый порт (если изменился)
             снимается ПОСЛЕ restart — он больше не слушается, экспозиции нет.
    """
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("vless_ws_cdn", {})
    current = ib.get("cdn_provider", "")
    port = ib.get("listen_port", 0)
    print()
    info(f"Текущий CDN: {CDN_PROVIDERS.get(current, {}).get('display_name', '—')}")
    new_provider = _pick_cdn_provider(exclude=current)
    if not new_provider:
        return

    # v4.23.2: авто-смена listen_port
    # Логика: сравниваем текущий listen_port с CDN_PROVIDERS[current]["default_port"].
    # Если равен — пользователь не менял порт вручную, переключаем на дефолт нового.
    # Если не равен — custom-порт, не трогаем, но warn().
    # Это менее надёжно чем отдельный флаг (listen_port_is_custom: bool) при совпадении
    # дефолтов двух провайдеров, но Gcore и Bunny имеют одинаковый дефолт (8443) —
    # switch между ними порт не меняет, что корректно. Cloudflare (8080) ≠ Gcore/Bunny
    # (8443) — switch всегда меняет порт, что тоже корректно.
    current_default = CDN_PROVIDERS.get(current, {}).get("default_port", 0)
    new_default = CDN_PROVIDERS.get(new_provider, {}).get("default_port", 0)
    old_port = port

    if port == current_default:
        # Порт = дефолт старого провайдера → переключаем на дефолт нового
        port = new_default
        if old_port != port:
            info(f"Порт изменён: {old_port} → {port} "
                 f"({CDN_PROVIDERS[new_provider]['display_name']} требует порт {port})")
    elif port != new_default:
        # Custom-порт, не равен дефолту нового провайдера → warn
        warn(f"Текущий порт {port} может быть невалиден для "
             f"{CDN_PROVIDERS[new_provider]['display_name']} "
             f"(рекомендуется {new_default}). Проверьте вручную.")

    # Сохраняем все остальные поля — меняем cdn_provider (+ порт если сменился)
    ib["cdn_provider"] = new_provider
    ib["listen_port"] = port
    singbox_state_update_inbound("vless_ws_cdn", **ib)

    # v4.23.3: allowlist применяется ДО generate_config/restart.
    # Порядок критичен: если restart откроет порт ДО apply_cdn_allowlist,
    # возникает окно (от секунды до нескольких, пока идёт сетевой fetch
    # CDN IP-листа) когда порт открыт всем интернету без allowlist.
    # Правильный порядок:
    #   1. remove_cdn_allowlist(port) — очистка старого allowlist на новом порту
    #      (мог остаться от предыдущего провайдера на том же порту)
    #   2. apply_cdn_allowlist(new_provider, port) — новый allowlist встаёт
    #   3. singbox_generate_config() + singbox_restart() — sing-box стартует
    #      на уже защищённом порту
    #   4. remove_cdn_allowlist(old_port) — старый порт больше не слушается,
    #      снимаем allowlist (если port != old_port). Это не создаёт экспозиции —
    #      sing-box уже не слушает old_port.
    if port:
        try:
            from vless_installer.modules.singbox_cdn_nets import (
                remove_cdn_allowlist, apply_cdn_allowlist,
            )
            # 1. Очищаем старый allowlist на новом порту (если был)
            remove_cdn_allowlist(port)
            # 2. Применяем новый allowlist ДО restart
            allowlist_ok = apply_cdn_allowlist(new_provider, port)
            if not allowlist_ok:
                warn(f"Allowlist не применён — sing-box restart произойдёт "
                     f"на НЕЗАЩИЩЁННЫЙ порт {port}!")
        except Exception as e:
            warn(f"Allowlist не применён: {e}")
            warn(f"Sing-box restart произойдёт на НЕЗАЩИЩЁННЫЙ порт {port}!")

    # 3. Генерируем конфиг и перезапускаем sing-box (порт уже защищён)
    singbox_generate_config()
    if _service_active():
        singbox_restart()

    # 4. Снимаем allowlist со старого порта (если порт изменился).
    # Старый порт больше не слушается sing-box — экспозиции нет.
    if old_port and old_port != port:
        try:
            from vless_installer.modules.singbox_cdn_nets import remove_cdn_allowlist
            remove_cdn_allowlist(old_port)
        except Exception:
            pass  # не критично — порт больше не слушается

    success(f"CDN переключён: {CDN_PROVIDERS[current]['display_name'] if current else '—'} → "
            f"{CDN_PROVIDERS[new_provider]['display_name']}")
    info("WS path, Host и UUID сохранены — клиентам нужно только сменить адрес подключения")
    _show_cdn_instructions(new_provider)


def _change_vless_ws_cdn_host() -> None:
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("vless_ws_cdn", {})
    try:
        new_host = input(
            f"{CYAN}Новый Host {DIM}(текущий={ib.get('host', '')}):{NC} "
        ).strip()
    except KeyboardInterrupt:
        return
    if not new_host:
        return
    ib["host"] = new_host
    singbox_state_update_inbound("vless_ws_cdn", **ib)
    singbox_generate_config()
    if not _apply_and_check("Host изменён, но sing-box не запустился"):
        return
    success(f"Host: {new_host}")


def _regen_vless_ws_cdn_path() -> None:
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("vless_ws_cdn", {})
    new_path = _gen_random_ws_path()
    ib["ws_path"] = new_path
    singbox_state_update_inbound("vless_ws_cdn", **ib)
    singbox_generate_config()
    if not _apply_and_check("WS path изменён, но sing-box не запустился"):
        return
    success(f"WS path: {new_path}")
    warn("ВНИМАНИЕ: клиентам нужно раздать новый WS path!")


def _regen_vless_ws_cdn_uuid() -> None:
    from vless_installer.modules.singbox_config import _gen_vless_uuid
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("vless_ws_cdn", {})
    new_uuid = _gen_vless_uuid()
    ib["uuid"] = new_uuid
    singbox_state_update_inbound("vless_ws_cdn", **ib)
    singbox_generate_config()
    if not _apply_and_check("UUID изменён, но sing-box не запустился"):
        return
    success(f"UUID: {new_uuid}")
    warn("ВНИМАНИЕ: клиентам нужно раздать новый UUID!")


def _pick_cdn_provider(exclude: str = "") -> str:
    """Интерактивный выбор CDN-провайдера. Возвращает ключ или пустую строку."""
    print()
    info("Выберите CDN-провайдера:")
    providers = [(k, v) for k, v in CDN_PROVIDERS.items() if k != exclude]
    for i, (key, meta) in enumerate(providers, 1):
        info(f"  {i}. {meta['display_name']}")
    try:
        choice = input(f"{CYAN}Выбор (1-{len(providers)}):{NC} ").strip()
        idx = int(choice) - 1
        if 0 <= idx < len(providers):
            return providers[idx][0]
    except (ValueError, KeyboardInterrupt):
        pass
    warn("Неверный выбор")
    return ""


def _show_cdn_instructions(cdn_provider: str) -> None:
    """Показывает инструкцию по настройке CDN-панели для выбранного провайдера."""
    meta = CDN_PROVIDERS.get(cdn_provider)
    if not meta:
        warn(f"Неизвестный CDN-провайдер: {cdn_provider}")
        return
    os.system("clear")
    print()
    _box_top(f"📖  ИНСТРУКЦИЯ НАСТРОЙКИ {meta['display_name'].upper()}")
    _box_desc(
        "Эти шаги нужно выполнить в панели CDN ВРУЧНУЮ. "
        "Установщик не дёргает CDN API — только origin-side конфиг."
    )
    _box_sep()
    for line in meta["instructions"]:
        if line:
            _box_row(f"  {line}")
        else:
            _box_row()
    _box_sep()
    _box_info("После настройки панели — проверьте подключение клиентом.")
    _box_info(f"CDN CNAME должен указывать на ваш origin (IP сервера, порт 8443).")
    _box_bottom()


# ============================================================================
#  Подменю: SNI-dispatch
# ============================================================================
def _sni_dispatch_menu() -> None:
    while True:
        os.system("clear")
        print()
        st = sni_dispatch_status()

        _box_top("🔀  SNI-DISPATCH (nginx stream + ssl_preread)")
        enabled = st["enabled"]
        col = GREEN if enabled else YELLOW
        _box_row(f"  Статус:              {col}{'включён' if enabled else 'выключен'}{NC}")
        _box_row(f"  ShadowTLS SNI:       {CYAN}{st.get('shadowtls_sni', '') or '—'}{NC}")
        _box_row(f"  AnyTLS SNI:          {CYAN}{st.get('anytls_sni', '') or '—'}{NC}")
        _box_row(f"  Default → Reality:   {CYAN}{st.get('default_backend', '') or '—'}{NC}")
        _box_row(f"  nginx stream support: "
                 f"{GREEN if st['nginx_stream_support'] else RED}{st['nginx_stream_support']}{NC}")
        _box_row(f"  ssl_preread:         "
                 f"{GREEN if st['nginx_ssl_preread'] else RED}{st['nginx_ssl_preread']}{NC}")
        _box_row(f"  stream{{}} в nginx.conf:  "
                 f"{GREEN if st['nginx_stream_block'] else YELLOW}{st['nginx_stream_block']}{NC}")
        _box_row(f"  Конфиг-файл:         "
                 f"{GREEN if st['config_file_exists'] else DIM}{st['nginx_stream_conf']}{NC}")
        _box_sep()
        _box_desc(
            "SNI-dispatch через nginx stream{} + ssl_preread — диспетчеризация "
            "TCP:443 по полю SNI в ClientHello. Reality, ShadowTLS, AnyTLS "
            "живут на одном порту под разными доменами. ВНИМАНИЕ: при "
            "включении Reality переезжает на backend (loopback:8442)!"
        )
        _box_sep()
        _box_row()
        if enabled:
            _box_item("1", f"🔴 Выключить SNI-dispatch  {DIM}вернуть Reality на :443{NC}")
            _box_item("2", f"🧪 Проверить конфиг        {DIM}nginx -t{NC}")
        else:
            _box_item("1", f"🤖 Auto-config              {DIM}auto-detect SNI + backend + миграция listen 443{NC}  {DIM}(NEW){NC}")
            _box_item("2", f"⚙️  Включить вручную         {DIM}с указанием SNI-доменов{NC}")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", ""):
            break

        if enabled:
            if ch == "1":
                # v4.23.6: используем auto_disable если auto_configured
                from vless_installer.modules.singbox_nginx import auto_disable_sni_dispatch
                auto_disable_sni_dispatch(interactive=True)
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                from vless_installer.modules.singbox_nginx import validate_sni_dispatch_config
                if validate_sni_dispatch_config():
                    success("Конфиг валиден")
                else:
                    error("Конфиг невалиден — проверьте nginx -t")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
        else:
            if ch == "1":
                # v4.23.6: auto-config
                from vless_installer.modules.singbox_nginx import auto_enable_sni_dispatch
                auto_enable_sni_dispatch(interactive=True)
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "2":
                # Ручной режим (старый путь)
                try:
                    sh_sni = input(f"{CYAN}ShadowTLS SNI {DIM}(напр. shadowtls.example.com):{NC} ").strip()
                    an_sni = input(f"{CYAN}AnyTLS SNI {DIM}(напр. anytls.example.com):{NC} ").strip()
                    backend = input(
                        f"{CYAN}Default backend {DIM}(Enter=127.0.0.1:8442):{NC} "
                    ).strip() or "127.0.0.1:8442"
                except KeyboardInterrupt:
                    continue
                enable_sni_dispatch(
                    shadowtls_sni=sh_sni,
                    anytls_sni=an_sni,
                    default_backend=backend,
                    interactive=True,
                )
                input(f"\n{BLUE}Нажмите Enter...{NC}")


# ============================================================================
#  Подменю: Синхронизация users
# ============================================================================
def _sync_users_menu() -> None:
    os.system("clear")
    print()
    _box_top("👥  СИНХРОНИЗАЦИЯ USERS С UNIFIED")
    unified = singbox_get_users()
    _box_row(f"  Unified users (из Xray): {CYAN}{len(unified)}{NC}")
    _box_sep()
    if not unified:
        _box_warn("Нет unified users — добавьте VLESS-пользователей в меню 2")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    for u in unified[:20]:  # показываем первые 20
        name = u.get("name", u.get("email", ""))[:32]
        uuid_short = u.get("uuid", "")[:8]
        _box_row(f"  {GREEN}•{NC} {name:<32}  {DIM}{uuid_short}…{NC}")
    if len(unified) > 20:
        _box_row(f"  {DIM}…и ещё {len(unified) - 20}{NC}")
    _box_sep()

    enabled_protos = singbox_state_get_enabled_protocols()
    if not enabled_protos:
        _box_warn("Нет включённых протоколов sing-box — нечего синхронизировать")
    else:
        _box_row(f"  Активные протоколы: {CYAN}{', '.join(enabled_protos)}{NC}")
        _box_info("Сейчас будет выполнена синхронизация: UUID из unified добавятся")
        _box_info("во все включённые inbound'ы sing-box (с генерацией паролей).")
    _box_bottom()

    if not enabled_protos:
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    try:
        confirm = input(f"{YELLOW}Запустить синхронизацию? (y/N):{NC} ").strip().lower()
    except KeyboardInterrupt:
        confirm = ""
    if confirm != "y":
        return

    result = singbox_sync_users()
    singbox_generate_config()
    if not _apply_and_check("Синхронизация выполнена, но sing-box не запустился"):
        return

    print()
    success(f"Синхронизация завершена: +{result['added']} добавлено, "
            f"-{result['removed']} удалено, ={result['kept']} оставлено")
    input(f"\n{BLUE}Нажмите Enter...{NC}")


# ============================================================================
#  Подменю: Управление сервисом
# ============================================================================
def _service_menu() -> None:
    while True:
        os.system("clear")
        print()
        active = _service_active()
        col = GREEN if active else RED
        _box_top("🔄  УПРАВЛЕНИЕ СЕРВИСОМ")
        _box_row(f"  Статус: {col}{'активен' if active else 'DOWN'}{NC}")
        _box_sep()
        _box_row()
        if active:
            _box_item("1", f"🔴 Остановить sing-box")
            _box_item("2", f"🔄 Перезапустить sing-box")
            _box_item("3", f"📋 Показать последние логи")
        else:
            _box_item("1", f"🟢 Запустить sing-box")
            _box_item("2", f"🔄 Перезапустить sing-box")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break

        if ch in ("0", ""):
            break
        elif ch == "1":
            if active:
                singbox_stop()
            else:
                if not SINGBOX_CONFIG_FILE.exists():
                    warn("Конфиг не найден — сначала включите хотя бы один протокол")
                    time.sleep(1.5)
                    continue
                singbox_start()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            break
        elif ch == "2":
            singbox_restart()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            break
        elif ch == "3" and active:
            _show_logs()


# ============================================================================
#  Подменю: Статус
# ============================================================================
def _show_status() -> None:
    os.system("clear")
    print()
    st = singbox_status()
    _box_top("📊  ПОЛНЫЙ СТАТУС SING-BOX")
    _box_row(f"  Бинарник:        "
             f"{GREEN if st['binary_installed'] else RED}"
             f"{'установлен' if st['binary_installed'] else 'не установлен'}{NC}")
    if st["binary_version"]:
        _box_row(f"  Версия:          {CYAN}v{st['binary_version']}{NC}")
    _box_row(f"  Конфиг:          "
             f"{GREEN if st['config_exists'] else RED}"
             f"{'есть' if st['config_exists'] else 'отсутствует'}{NC}  "
             f"{DIM}{SINGBOX_CONFIG_FILE}{NC}")
    _box_row(f"  Сервис:          "
             f"{GREEN if st['service_active'] else RED}"
             f"{'active' if st['service_active'] else 'inactive'}{NC}")
    _box_row(f"  Enabled:         "
             f"{GREEN if st['service_enabled'] else DIM}"
             f"{'yes' if st['service_enabled'] else 'no'}{NC}")

    enabled_protos = singbox_state_get_enabled_protocols()
    _box_row(f"  Протоколов вкл.: {CYAN}{len(enabled_protos)}{NC}  "
             f"{DIM}{', '.join(enabled_protos) if enabled_protos else '(нет)'}{NC}")
    _box_sep()

    state = singbox_state_load()
    inbounds = state.get("inbounds", {})
    for proto, ib in inbounds.items():
        if proto == "trojan":
            continue  # внутренний
        enabled = ib.get("enabled", False)
        port = ib.get("listen_port", "?")
        listen = ib.get("listen", "?")
        n_users = len(ib.get("users", []))
        col = GREEN if enabled else DIM
        _box_row(f"  {col}•{NC} {proto:<12}  {listen}:{port}  users={n_users}")
    _box_sep()

    sd = state.get("sni_dispatch", {})
    if sd.get("enabled"):
        _box_row(f"  SNI-dispatch:   {GREEN}включён{NC}")
        _box_row(f"    ShadowTLS SNI: {CYAN}{sd.get('shadowtls_sni', '')}{NC}")
        _box_row(f"    AnyTLS SNI:    {CYAN}{sd.get('anytls_sni', '')}{NC}")
    else:
        _box_row(f"  SNI-dispatch:   {DIM}выключен{NC}")
    _box_bottom()


# ============================================================================
#  Подменю: Логи
# ============================================================================
def _show_logs() -> None:
    """Просмотр логов sing-box через journalctl (v4.23.10).

    Раньше читал /var/log/singbox.log напрямую, но после перехода на
    StandardOutput/Error=journal логи пишутся только в journald.
    """
    os.system("clear")
    print()
    _box_top("📋  ЛОГИ SING-BOX (journalctl)")
    _box_row(f"  {DIM}Источник: journald (StandardOutput/Error=journal){NC}")
    _box_row()
    r = _run(["journalctl", "-u", SINGBOX_SERVICE, "-n", "40",
              "--no-pager"], capture=True, quiet=True)
    lines = (r.stdout or "").splitlines()
    if not lines:
        _box_row(f"  {YELLOW}Логи пусты — сервис ни разу не запускался{NC}")
        _box_row()
    else:
        for line in lines:
            _box_row(f"  {DIM}{line[:140]}{NC}")
        _box_row()
        _box_row(f"  {CYAN}Хвост лога в реальном времени:{NC}")
        _box_row(f"  {DIM}journalctl -u {SINGBOX_SERVICE} -f{NC}")
        _box_row()
    _box_item_exit("0", "← Назад")
    _box_bottom()
    try:
        input(f"{CYAN}Нажмите Enter...{NC}")
    except KeyboardInterrupt:
        pass


# ============================================================================
#  Подменю: Удаление
# ============================================================================
def _uninstall_menu() -> None:
    os.system("clear")
    print()
    _box_top("🗑️  УДАЛЕНИЕ SING-BOX")
    _box_warn("Будет удалено:")
    _box_row(f"  • systemd-юнит sing-box.service")
    _box_row(f"  • бинарник {SINGBOX_BINARY}")
    _box_row(f"  • конфиг /etc/sing-box/ (включая сертификаты)")
    _box_row(f"  • state-файл singbox_state.json")
    _box_row(f"  • SNI-dispatch конфиг (если включён)")
    _box_row(f"  • UFW-правила sing-box (только наши, чужие не трогаем)")
    _box_sep()
    _box_warn("Xray / Nginx / Hysteria2 / AWG — НЕ затрагиваются.")
    _box_bottom()

    try:
        confirm = input(f"{YELLOW}Удалить sing-box? (y/N):{NC} ").strip().lower()
    except KeyboardInterrupt:
        confirm = ""
    if confirm != "y":
        info("Отменено")
        return

    # Сначала выключаем SNI-dispatch если включён
    sd = sni_dispatch_status()
    if sd["enabled"]:
        info("Выключаю SNI-dispatch...")
        disable_sni_dispatch(interactive=False)

    # v4.23.14: закрываем все наши UFW-правила (только sing-box-*)
    info("Закрываю UFW-правила sing-box...")
    singbox_ufw_close_all()

    singbox_uninstall_binary()
    input(f"\n{BLUE}Нажмите Enter...{NC}")


# ============================================================================
#  Вспомогательные функции
# ============================================================================
def _ensure_binary_installed() -> bool:
    """Проверяет что бинарник установлен, иначе предлагает установить."""
    if _singbox_binary_exists():
        return True
    warn("Бинарник sing-box не установлен")
    try:
        confirm = input(f"{YELLOW}Установить сейчас? (y/N):{NC} ").strip().lower()
    except KeyboardInterrupt:
        confirm = ""
    if confirm != "y":
        return False
    return singbox_install_binary()


def _ensure_self_signed_cert(prefix: str, common_name: str = "") -> tuple[Path, Path, str]:
    """Генерирует self-signed cert для sing-box протокола.

    v4.23.6: возвращает (cert_path, key_path, common_name) — common_name
    нужен для сохранения в state (auto-detect SNI в auto_enable_sni_dispatch).
    Если common_name не передан — используется f"sing-box-{prefix}" как раньше.

    v4.23.7: Если cert уже существует на диске — парсит РЕАЛЬНЫЙ CN из файла
    через openssl x509 -noout -subject, а не возвращает переданный common_name.
    Иначе при смене домена сервера и повторном вызове с новым common_name
    функция вернёт cn, не соответствующий физическому сертификату, что
    приведёт к неверной SNI-маршрутизации в auto_enable_sni_dispatch().
    """
    from vless_installer.modules.singbox_common import generate_self_signed_cert
    cert_path = SINGBOX_CERT_DIR / f"{prefix}.crt"
    key_path = SINGBOX_CERT_DIR / f"{prefix}.key"
    cn = common_name or f"sing-box-{prefix}"
    if cert_path.exists() and key_path.exists():
        # v4.23.7: парсим реальный CN из существующего сертификата
        real_cn = _parse_cn_from_cert(cert_path)
        if real_cn:
            return cert_path, key_path, real_cn
        # Если парсинг не удался — возвращаем переданный cn как fallback
        return cert_path, key_path, cn
    generate_self_signed_cert(
        common_name=cn,
        cert_path=cert_path,
        key_path=key_path,
    )
    return cert_path, key_path, cn


def _parse_cn_from_cert(cert_path: Path) -> str:
    """Парсит CN (Common Name) из существующего сертификата через openssl.

    Возвращает пустую строку при ошибке.
    """
    try:
        from vless_installer.modules.singbox_common import _run
        r = _run(["openssl", "x509", "-noout", "-subject", "-in", str(cert_path)],
                 capture=True, quiet=True)
        if r.returncode == 0 and r.stdout:
            subject = r.stdout.strip()
            # Вывод: "subject=C=XX, CN=example.com" или "subject=/CN=example.com"
            if "CN=" in subject:
                cn_part = subject.split("CN=")[-1].split(",")[0].split("/")[0].strip()
                if cn_part:
                    return cn_part
    except Exception:
        pass
    return ""


def _pick_letsencrypt_cert() -> tuple[Path, Path, str]:
    """Ищет существующий LE-сертификат в /etc/letsencrypt/live/.
    Возвращает (cert_path, key_path, "letsencrypt") или (None, None, "").
    """
    if not LE_LIVE_DIR.exists():
        return Path(), Path(), ""
    # Список доступных доменов
    domains = [d.name for d in LE_LIVE_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    if not domains:
        return Path(), Path(), ""

    print()
    info("Доступные LE-сертификаты:")
    for i, d in enumerate(domains, 1):
        info(f"  {i}. {d}")
    try:
        choice = input(f"{CYAN}Выбор (1-{len(domains)}):{NC} ").strip()
        idx = int(choice) - 1
        if idx < 0 or idx >= len(domains):
            return Path(), Path(), ""
        domain = domains[idx]
    except (ValueError, KeyboardInterrupt):
        return Path(), Path(), ""

    cert_path = LE_LIVE_DIR / domain / "fullchain.pem"
    key_path = LE_LIVE_DIR / domain / "privkey.pem"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path, "letsencrypt"
    return Path(), Path(), ""


def _regen_password(protocol: str) -> None:
    """Перегенерирует пароль у всех users в протоколе."""
    from vless_installer.modules.singbox_users import singbox_gen_password, singbox_gen_tuic_password
    state = singbox_state_load()
    ib = state.get("inbounds", {}).get(protocol, {})
    users = ib.get("users", [])
    if not users:
        warn(f"В протоколе {protocol} нет пользователей — нечего регенерировать")
        return
    for u in users:
        if protocol == "tuic":
            u["password"] = singbox_gen_tuic_password()
        else:
            u["password"] = singbox_gen_password()
    ib["users"] = users
    singbox_state_update_inbound(protocol, **ib)
    singbox_generate_config()
    if not _apply_and_check(f"Пароли {protocol} обновлены, но sing-box не запустился"):
        return
    success(f"Пароли {protocol} перегенерированы")
    warn("ВНИМАНИЕ: клиентам нужно раздать новые ссылки/пароли!")


def _list_users_for_protocol(protocol: str) -> None:
    users = singbox_state_list_users(protocol)
    os.system("clear")
    print()
    _box_top(f"👥  ПОЛЬЗОВАТЕЛИ {protocol.upper()}")
    if not users:
        _box_row(f"  {DIM}нет пользователей{NC}")
    else:
        for u in users:
            name = u.get("name", "")[:32]
            # v4.23.12: показываем полный пароль (раньше только обрезанный uuid,
            # что бесполезно для подключения клиента).
            pw = u.get("password", "")
            uuid_full = u.get("uuid", "")
            if uuid_full:
                # TUIC: uuid + password
                _box_row(f"  {GREEN}•{NC} {name:<24}  "
                         f"{CYAN}uuid={uuid_full}{NC}")
                _box_row(f"    {DIM}password={pw}{NC}")
            else:
                # ShadowTLS/AnyTLS/Trojan: только password
                _box_row(f"  {GREEN}•{NC} {name:<24}  "
                         f"{CYAN}password={pw}{NC}")
    _box_bottom()


# ============================================================================
#  Генерация клиентских ссылок (v4.23.12)
# ============================================================================
def _get_public_endpoint(state_ib: dict, default_listen: str = "127.0.0.1") -> tuple:
    """Возвращает (host, port) для подключения клиента извне.

    Логика:
      • Если listen == 0.0.0.0 или :: — клиент подключается к публичному IP сервера.
      • Если listen == 127.0.0.1 (loopback) — клиент НЕ может подключиться напрямую;
        нужно либо SNI-dispatch (TCP:443 → nginx stream → backend), либо сменить listen.
        Возвращаем публичный IP с пометкой 'loopback_warning'.
    """
    listen = state_ib.get("listen", default_listen)
    port = state_ib.get("listen_port", 0)
    is_loopback = listen in ("127.0.0.1", "::1", "localhost")
    # Публичный IP сервера
    public_ip = ""
    try:
        from vless_installer.modules.resources import get_server_ip
        public_ip = get_server_ip("4") or ""
    except Exception:
        pass
    if is_loopback:
        return public_ip, port, True
    return public_ip or listen, port, False


def _gen_shadowtls_client_uri(state_ib: dict, public_ip: str, port: int,
                              password: str) -> str:
    """Генерирует trojan:// URI для ShadowTLS v3 + Trojan.

    Формат (понимается Hiddify/Nekobox/Karing/sing-box):
      trojan://<password>@<host>:<port>?security=tls&sni=<handshake_domain>
        &shadowtls=3&shadowtls_password=<password>#<name>

    Важно: в sing-box клиентский outbound для ShadowTLS v3 использует
    type=trojan + transport=shadowtls. URI выше — устоявшийся де-факто
    стандарт, понимаемый GUI-клиентами.
    """
    handshake = state_ib.get("handshake", {})
    sni = handshake.get("server", "www.cloudflare.com")
    name = state_ib.get("users", [{}])[0].get("name", "shadowtls-user") \
        if state_ib.get("users") else "shadowtls-user"
    from urllib.parse import quote, urlencode
    params = urlencode({
        "security": "tls",
        "sni": sni,
        "shadowtls": "3",
        "shadowtls_password": password,
        "fp": "chrome",
    })
    return f"trojan://{quote(password, safe='')}@{public_ip}:{port}?{params}#{quote(name)}"


def _gen_anytls_client_uri(state_ib: dict, public_ip: str, port: int,
                           password: str) -> str:
    """Генерирует anytls:// URI (sing-box >= 1.10)."""
    name = state_ib.get("users", [{}])[0].get("name", "anytls-user") \
        if state_ib.get("users") else "anytls-user"
    from urllib.parse import quote, urlencode
    # SNI для AnyTLS: общий домен (если есть), иначе публичный IP
    sni = state_ib.get("common_name") or public_ip
    params = urlencode({
        "sni": sni,
        "insecure": "1" if state_ib.get("cert_source") == "self-signed" else "0",
    })
    return f"anytls://{quote(password, safe='')}@{public_ip}:{port}?{params}#{quote(name)}"


def _gen_tuic_client_uri(state_ib: dict, public_ip: str, port: int) -> str:
    """Генерирует tuic:// URI для TUIC v5."""
    users = state_ib.get("users", [])
    if not users:
        return ""
    u = users[0]
    uuid = u.get("uuid", "")
    password = u.get("password", "")
    name = u.get("name", "tuic-user")
    from urllib.parse import quote, urlencode
    congestion = state_ib.get("congestion_control", "bbr")
    params = urlencode({
        "congestion_control": congestion,
        "alpn": "h3",
        "sni": public_ip,
        "allow_insecure": "1" if state_ib.get("cert_source") == "self-signed" else "0",
    })
    return f"tuic://{uuid}:{quote(password, safe='')}@{public_ip}:{port}?{params}#{quote(name)}"


def _gen_vless_ws_cdn_client_uri(state_ib: dict) -> str:
    """Генерирует vless:// URI для VLESS+WS+CDN."""
    uuid = state_ib.get("uuid", "")
    host = state_ib.get("host", "")
    port = 443  # CDN endpoint всегда 443 (CDN терминирует TLS)
    ws_path = state_ib.get("ws_path", "/")
    from urllib.parse import quote, urlencode
    params = urlencode({
        "encryption": "none",
        "security": "tls",
        "sni": host,
        "type": "ws",
        "host": host,
        "path": ws_path,
    })
    return f"vless://{uuid}@{host}:{port}?{params}#{quote(host)}"


def _get_effective_password(state_ib: dict) -> str:
    """Возвращает пароль, который РЕАЛЬНО работает в sing-box (v4.23.20).

    Приоритет:
      1. state_ib['users'][0]['password'] — это то, что попадает в config.json
         и проверяется sing-box при авторизации.
      2. state_ib['password'] — fallback для старых state-файлов без users[].

    Раньше генераторы URI/JSON брали state_ib['password'], но он рассинхронизирован
    с users[].password при singbox_enable_*() — password обновляется, users[].password
    остаётся старый. Отсюда 'unknown user password' в логе sing-box.

    См. коммит v4.23.20 — подробное описание бага.
    """
    if state_ib.get("users"):
        pw = state_ib["users"][0].get("password", "")
        if pw:
            return pw
    return state_ib.get("password", "")


def _gen_singbox_client_json(protocol: str, state_ib: dict,
                             public_ip: str, port: int) -> str:
    """Генерирует полный клиентский config.json для sing-box 1.12+.

    v4.23.15: ПОЛНЫЙ КОНФИГ, не фрагмент. Готов к запуску:
      sing-box run -c client-config.json

    ВАЖНО для ShadowTLS (v4.23.15):
      В sing-box 1.12+ ShadowTLS — это отдельный тип outbound (type: shadowtls),
      НЕ transport. Правильная схема:
        - shadowtls-out: подключается к серверу, делает shadowtls-handshake
        - trojan-out: использует shadowtls-out как транспорт (detour)
      Старый формат с transport: shadowtls больше НЕ работает (sing-box 1.13
      выдаёт 'unknown transport type: shadowtls').

    v4.23.20: пароль берётся через _get_effective_password() — из users[].password,
    не из state.password (рассинхрон).
    """
    import json as _json
    # Базовый шаблон полного клиентского конфига
    # listen_port 2080 — стандартный SOCKS/mixed-прокси для клиента
    base = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
        }],
        "outbounds": [],
        "route": {"final": "proxy"},
    }

    if protocol == "shadowtls":
        handshake = state_ib.get("handshake", {})
        sni = handshake.get("server", "www.cloudflare.com")
        password = _get_effective_password(state_ib)
        # v4.23.16: правильная схема для sing-box 1.12+
        # shadowtls outbound — НЕ имеет detour (конечный outbound, делает
        # TLS-handshake к handshake.server, например www.cloudflare.com)
        # trojan outbound — имеет detour: "proxy" (использует shadowtls
        # как транспорт для своего трафика)
        #
        # ВАЖНО: detour в shadowtls outbound создавать НЕЛЬЗЯ — это создаёт
        # circular dependency (proxy → trojan-out → proxy), sing-box падает
        # с 'circular outbound dependency' (найдено через Karing).
        base["outbounds"] = [
            {
                "type": "shadowtls",
                "tag": "proxy",
                "server": public_ip,
                "server_port": port,
                "version": 3,
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                },
                # НЕ добавляем detour здесь — это создаст цикл!
            },
            {
                "type": "trojan",
                "tag": "trojan-out",
                "server": public_ip,
                "server_port": port,
                "password": password,
                "detour": "proxy",  # trojan использует shadowtls как транспорт
            },
            {"type": "direct", "tag": "direct"},
        ]
    elif protocol == "anytls":
        password = _get_effective_password(state_ib)
        sni = state_ib.get("common_name") or public_ip
        base["outbounds"] = [
            {
                "type": "anytls",
                "tag": "proxy",
                "server": public_ip,
                "server_port": port,
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "insecure": state_ib.get("cert_source") == "self-signed",
                },
            },
            {"type": "direct", "tag": "direct"},
        ]
    elif protocol == "tuic":
        users = state_ib.get("users", [])
        if not users:
            return ""
        u = users[0]
        base["outbounds"] = [
            {
                "type": "tuic",
                "tag": "proxy",
                "server": public_ip,
                "server_port": port,
                "uuid": u.get("uuid", ""),
                "password": u.get("password", ""),
                "congestion_control": state_ib.get("congestion_control", "bbr"),
                "tls": {
                    "enabled": True,
                    "server_name": public_ip,
                    "insecure": state_ib.get("cert_source") == "self-signed",
                },
            },
            {"type": "direct", "tag": "direct"},
        ]
    elif protocol == "vless_ws_cdn":
        base["outbounds"] = [
            {
                "type": "vless",
                "tag": "proxy",
                "server": state_ib.get("host", ""),
                "server_port": 443,
                "uuid": state_ib.get("uuid", ""),
                "tls": {
                    "enabled": True,
                    "server_name": state_ib.get("host", ""),
                },
                "transport": {
                    "type": "ws",
                    "path": state_ib.get("ws_path", "/"),
                    "headers": {"Host": state_ib.get("host", "")},
                },
            },
            {"type": "direct", "tag": "direct"},
        ]
    else:
        return ""
    return _json.dumps(base, indent=2, ensure_ascii=False)


def _show_client_links(protocol: str) -> None:
    """Показывает клиентские ссылки/QR/JSON для протокола.

    v4.23.12: решает проблему 'где взять ссылку для подключения клиента?'.
    Раньше пункт 'Показать пользователей' показывал только обрезанный uuid,
    без пароля и без готового URI. Теперь показывает:
      • Внешний endpoint (host:port)
      • Предупреждение о loopback, если listen=127.0.0.1
      • URI для импорта в GUI-клиент (Hiddify/Nekobox/Karing/sing-box)
      • JSON outbound для ручной конфигурации sing-box
      • QR-код в терминале (если установлен qrencode)
    """
    state = singbox_state_load()
    inbounds = state.get("inbounds", {})
    state_ib = inbounds.get(protocol, {})
    if not state_ib.get("enabled", False):
        warn(f"Протокол {protocol} не включён — ссылки недоступны")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    # Определяем публичный endpoint
    default_listen = "127.0.0.1" if protocol in ("shadowtls", "anytls") else "::"
    public_ip, port, is_loopback = _get_public_endpoint(state_ib, default_listen)

    # v4.23.20: пароль для URI/JSON берём через _get_effective_password() —
    # из users[0].password (то, что реально работает в sing-box), не из
    # state.password (рассинхрон с users[].password).
    password = _get_effective_password(state_ib)

    # Генерируем URI
    if protocol == "shadowtls":
        uri = _gen_shadowtls_client_uri(state_ib, public_ip, port, password)
    elif protocol == "anytls":
        uri = _gen_anytls_client_uri(state_ib, public_ip, port, password)
    elif protocol == "tuic":
        uri = _gen_tuic_client_uri(state_ib, public_ip, port)
    elif protocol == "vless_ws_cdn":
        uri = _gen_vless_ws_cdn_client_uri(state_ib)
    else:
        warn(f"Для протокола {protocol} генерация ссылок не поддерживается")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    os.system("clear")
    print()
    _box_top(f"🔗  КЛИЕНТСКИЕ ССЫЛКИ — {protocol.upper()}")

    # Endpoint
    _box_row(f"  {BOLD}Endpoint:{NC}  {CYAN}{public_ip}:{port}{NC}")
    if is_loopback:
        _box_sep()
        _box_row(f"  {YELLOW}⚠  Внимание: listen=127.0.0.1 (loopback){NC}")
        _box_row(f"  {DIM}Клиент извне НЕ сможет подключиться напрямую.{NC}")
        _box_row(f"  {DIM}Варианты:{NC}")
        _box_row(f"  {DIM}  1. SNI-dispatch (меню 5) — TCP:443 → nginx stream → backend{NC}")
        _box_row(f"  {DIM}     маршрутизирует по SNI на {public_ip}:{port}{NC}")
        _box_row(f"  {DIM}  2. Сменить Listen IP на 0.0.0.0 (меню 6 для ShadowTLS,{NC}")
        _box_row(f"  {DIM}     меню 5 для AnyTLS) + ufw allow {port}/tcp{NC}")

    # URI
    _box_sep()
    _box_row(f"  {BOLD}URI для импорта в клиент:{NC}")
    _box_row(f"  {CYAN}{uri}{NC}")

    # JSON
    _box_sep()
    _box_row(f"  {BOLD}Полный sing-box client config.json (v4.23.15):{NC}")
    _box_row(f"  {DIM}Сохраните как config.json → sing-box run -c config.json{NC}")
    _box_row(f"  {DIM}Прокси 127.0.0.1:2080 (mixed). НЕ включайте системный{NC}")
    _box_row(f"  {DIM}прокси Windows — используйте SwitchyOmega или импорт в клиент.{NC}")
    _box_row(f"  {DIM}Запуск на Windows: sing-box.exe run -c config.json{NC}")
    json_str = _gen_singbox_client_json(protocol, state_ib, public_ip, port)
    if json_str:
        for line in json_str.splitlines():
            _box_row(f"  {DIM}{line}{NC}")

    # v4.23.17: примечание про клиентов и импорт JSON
    if protocol == "shadowtls":
        _box_sep()
        _box_row(f"  {YELLOW}⚠  Про клиентов (важно):{NC}")
        _box_row(f"  {DIM}• URI (ссылка выше) в Hiddify/Nekobox НЕ работает для ShadowTLS v3 —{NC}")
        _box_row(f"  {DIM}  баг парсера URI: shadowtls_password теряется → 'hmac mismatch'.{NC}")
        _box_row(f"  {DIM}• Karing: импорт JSON работает. Создаёт 2 профиля (proxy и proxy-out) —{NC}")
        _box_row(f"  {DIM}  используйте proxy-out (с detour), proxy НЕ подключается.{NC}")
        _box_row(f"  {DIM}• v2rayN (Windows): импорт JSON возможен, но не проверен.{NC}")
        _box_row(f"  {DIM}  Если работает — используйте его.{NC}")
        _box_row(f"  {DIM}• sing-box CLI (Linux/macOS/Windows): sing-box run -c config.json{NC}")
        _box_row(f"  {DIM}  + SwitchyOmega в браузере на 127.0.0.1:2080.{NC}")

    # QR-код
    _box_sep()
    try:
        import shutil as _sh
        qrencode = _sh.which("qrencode")
    except Exception:
        qrencode = None
    if qrencode:
        import subprocess as _sp
        _box_row(f"  {BOLD}QR-код:{NC}")
        r = _sp.run(
            [qrencode, "-t", "ANSIUTF8", "-m", "1", "-o", "-", uri],
            capture_output=True, text=True
        )
        if r.stdout:
            for line in r.stdout.splitlines():
                _box_row(f"  {line}")
        else:
            _box_row(f"  {DIM}(qrencode не смог сгенерировать QR){NC}")
    else:
        _box_row(f"  {DIM}Для QR-кода установите: apt install qrencode{NC}")

    _box_sep()
    _box_row(f"  {DIM}Клиенты: Hiddify, Nekobox, Karing, sing-box GUI, v2rayN{NC}")
    _box_row(f"  {DIM}Импорт: скопируйте URI → вставьте в клиент → Connect{NC}")
    _box_bottom()
    try:
        input(f"{CYAN}Нажмите Enter...{NC}")
    except KeyboardInterrupt:
        pass


def _list_users_for_protocol(protocol: str) -> None:
    users = singbox_state_list_users(protocol)
    os.system("clear")
    print()
    _box_top(f"👥  ПОЛЬЗОВАТЕЛИ {protocol.upper()}")
    if not users:
        _box_row(f"  {DIM}нет пользователей{NC}")
    else:
        for u in users:
            name = u.get("name", "")[:32]
            # v4.23.12: показываем полный пароль (раньше только обрезанный uuid,
            # что бесполезно для подключения клиента).
            pw = u.get("password", "")
            uuid_full = u.get("uuid", "")
            if uuid_full:
                # TUIC: uuid + password
                _box_row(f"  {GREEN}•{NC} {name:<24}  "
                         f"{CYAN}uuid={uuid_full}{NC}")
                _box_row(f"    {DIM}password={pw}{NC}")
            else:
                # ShadowTLS/AnyTLS/Trojan: только password
                _box_row(f"  {GREEN}•{NC} {name:<24}  "
                         f"{CYAN}password={pw}{NC}")
    _box_bottom()
