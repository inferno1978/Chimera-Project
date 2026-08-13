"""
chimera/modules/users_manager.py
───────────────────────────────────────────────────────────────────────────────
Управление пользователями Xray (добавление / удаление / ссылки / статистика).

Содержит 16 функций, вынесенных из _core.py тремя блоками:

Region A — базовый CRUD пользователей (clients в xray config.json):
  • ``_users_get_config()``                          — найти config.json Xray.
  • ``_users_apply_config(cfg)``                     — применить конфиг (test +
    restart через ``_xray_safe_apply_config``).
  • ``_users_gen_link(cfg, uuid_str, email)``        — VLESS-ссылка из
    фактического config.json (REALITY/xHTTP).
  • ``do_user_list()``                               — список пользователей.
  • ``do_user_add()``                                — добавить пользователя.
  • ``do_user_delete()``                             — удалить пользователя.
  • ``_show_qr(link, label, png_path)``              — QR-код в боксе.
  • ``_gen_vless_link(host, uuid_str, pbk, sid, ...)``— сборщик VLESS-ссылки.
  • ``generate_client_links()``                      — генерация всех ссылок
    (IPv4/IPv6/Domain) для основного пользователя. Мутирует ``_BOX_W``.

  Удалены в патче №5 (мёртвый код, строго подмножество do_unified_user_manager
  из _core.py, доступного из главного меню 2 → 1):
  • ``do_user_show_link()`` — вызывалась только из do_user_menu().
  • ``do_user_menu()``      — не вызывалась из _core.py, дублировала
    do_unified_user_manager() с меньшим набором пунктов.

Region B — единый менеджер (users.json + xray config.json одновременно):
  • ``_users_load()``                                — чтение users.json.
  • ``_users_save(users)``                           — запись users.json.
  • ``_users_patch_config_no_restart(users)``        — патч clients в config.json
    БЕЗ рестарта Xray.
  • ``_users_apply_to_config(users)``                — патч clients + restart
    Xray (с валидацией через ``xray run -test``).
  • ``_unified_load_users()``                        — объединённый список из
    users.json и config.json.
  • ``_unified_save_users(users)``                   — сохранение в оба формата.
  • ``_unified_show_links(u, print_output)``         — все ссылки (IPv4/IPv6/
    Domain) для пользователя.
  • ``_do_user_stats_screen(install_mode)``          — расширенный экран
    статистики (без сортировки).

Region C — v2 с сортировкой и экспортом CSV:
  • ``_do_user_stats_screen_v2(sort_key)``           — статистика с сортировкой
    + вызов ``_export_stats_csv``.

Точки входа из _core.py:
    from chimera.modules.users_manager import (
        _users_load, _users_save, _users_get_config, _users_apply_config,
        _users_apply_to_config, _users_patch_config_no_restart, _users_gen_link,
        do_user_list, do_user_add, do_user_delete,
        _show_qr, _gen_vless_link, generate_client_links,
        _unified_load_users, _unified_save_users, _unified_show_links,
        _do_user_stats_screen, _do_user_stats_screen_v2,
    )

Мутируемый глобал: ``_BOX_W`` (только в ``generate_client_links``) —
dual-form паттерн: ``_BOX_W = _get_box_width(); setattr(core, "_BOX_W", _BOX_W)``.

Доступ к helpers ядра (``_box_*``, ``_run``, ``warn``/``info``/``success``,
``_set_config_owner``, ``_xray_safe_apply_config``, ``_nginx_restart_if_reality``,
``_fp_from_state``, ``gen_uuid``, ``get_server_ip``, ``get_server_country_cached``,
``_get_box_width``, ``_users_get_outbound_breakdown``, ``_users_get_traffic``,
``_users_get_traffic_extended``, ``_fmt_bytes_ru``, ``_bar_mini``, ``_device_icon``,
``_do_user_stats_sorted``, ``_export_stats_csv``, ``log_to_file``, ``die``,
ANSI-цвета, ``STATE_FILE``, ``CONFIG_DIR``, ``USERS_FILE``, ``XRAY_BIN``,
``XRAY_STATS_API_PORT``, ``SERVER_PORT``, ``XTLS_FLOW``, ``PROTOCOL_MODE``,
``PARAM_*``, ``XHTTP_*``, ``AWG_EXIT_ENABLED``, ``IS_IPV6_AVAILABLE``,
``_STATS_SORT_KEYS``) — через importlib.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  Region A — БАЗОВЫЙ CRUD ПОЛЬЗОВАТЕЛЕЙ (clients в xray config.json)
# =============================================================================
def _users_get_config() -> Path:
    core = _core_module()
    die = core.die
    for p in (Path("/etc/xray/config.json"),
              Path("/usr/local/etc/xray/config.json")):
        if p.exists():
            return p
    die("Конфиг Xray не найден. Сначала выполните установку.")


def _users_apply_config(cfg: Path) -> None:
    """
    Применяет изменённый config.json к Xray.
    Делегирует в _xray_safe_apply_config (test → backup → restart → rollback).
    """
    core = _core_module()
    _xray_safe_apply_config = core._xray_safe_apply_config
    _xray_safe_apply_config(cfg)


def _users_gen_link(cfg: Path, uuid_str: str, email: str) -> str:
    core = _core_module()
    get_server_country_cached = core.get_server_country_cached
    get_server_ip             = core.get_server_ip
    PARAM_DOMAIN              = core.PARAM_DOMAIN
    _fp_from_state            = core._fp_from_state
    log_to_file               = core.log_to_file
    STATE_FILE                = getattr(core, "STATE_FILE", Path("/var/lib/xray-installer/state.json"))
    try:
        with cfg.open() as f:
            c = json.load(f)
        inb = c.get("inbounds", [{}])[0]
        ss  = inb.get("streamSettings", {})
        net = ss.get("network", "tcp")
        import urllib.parse
        _, _, _flag = get_server_country_cached()
        _flag_prefix = f"{_flag} " if _flag and _flag != "🌐" else ""
        label  = _flag_prefix + urllib.parse.quote(email)

        if net == "xhttp":
            xhttp_s = ss.get("xhttpSettings", {})
            path = xhttp_s.get("path", "/")
            mode = xhttp_s.get("mode", "stream-up")
            path_enc = urllib.parse.quote(path, safe="/")
            _fp = _fp_from_state()
            # ВАЖНО: после перехода на схему Nginx→Xray (loopback backend) Xray-inbound
            # слушает 127.0.0.1:XHTTP_BACKEND_PORT с security:none — без tlsSettings.
            # Поэтому port и domain больше нельзя читать из inbound-конфига
            # (там будет 8443 и пустой serverName). Берём их из state.json —
            # там хранятся SERVER_PORT (443, Nginx-сторона) и PARAM_DOMAIN.
            _st_domain = ""
            _st_port   = 443
            try:
                if STATE_FILE.exists():
                    _st = json.loads(STATE_FILE.read_text())
                    _st_domain = _st.get("domain", "") or PARAM_DOMAIN
                    _st_port   = int(_st.get("server_port", 443))
            except Exception:
                # fallback на PARAM_DOMAIN и 443 — не идеально, но ссылка будет рабочей
                _st_domain = PARAM_DOMAIN
                _st_port   = 443
            domain = _st_domain
            port   = _st_port
            # host = домен сервера (клиент подключается к Nginx на :443)
            host   = domain or get_server_ip("4") or ""
            return (f"vless://{uuid_str}@{host}:{port}"
                    f"?type=xhttp&security=tls&sni={domain}"
                    f"&path={path_enc}&mode={mode}"
                    f"&fp={_fp}#{label}")
        else:
            # REALITY-ветка: Xray сам слушает :SERVER_PORT с TLS, inbound-конфиг
            # содержит корректный port (== SERVER_PORT), realitySettings и т.д.
            # Тут чтение из inbound безопасно — оставляем как было.
            domain = ""
            port   = inb.get("port", 443)
            rs     = ss.get("realitySettings", {})
            sni    = (rs.get("serverNames") or [""])[0]
            pbk    = rs.get("publicKey", "")
            sids   = rs.get("shortIds", [""])
            sid    = sids[0] if sids else ""
            # host — реальный адрес сервера (PARAM_DOMAIN или IP), sni — домен маскировки
            host   = PARAM_DOMAIN or get_server_ip("4") or sni
            _fp = _fp_from_state()
            return (f"vless://{uuid_str}@{host}:{port}"
                    f"?type=tcp&security=reality&pbk={pbk}"
                    f"&fp={_fp}&sni={sni}&sid={sid}"
                    f"&flow=xtls-rprx-vision#{label}")
    except Exception as e:
        log_to_file("WARN", str(e))
        return ""


def do_user_list() -> None:
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    DIM         = core.DIM
    NC          = core.NC
    warn        = core.warn
    cfg = _users_get_config()
    _box_top("СПИСОК ПОЛЬЗОВАТЕЛЕЙ")
    try:
        with cfg.open() as f:
            c = json.load(f)
        clients = c.get("inbounds", [{}])[0].get("settings", {}).get("clients", [])
        # Разделяем реальных пользователей и iOS-shadow (по email с суффиксом __ios).
        # Shadow не нумеруются и не участвуют в выборе по номеру — они показываются
        # отдельным блоком внизу, чтобы админ видел, что они есть, но не путал их
        # с реальными юзерами.
        real_clients = [cl for cl in clients if not cl.get("email", "").endswith("__ios")]
        shadow_clients = [cl for cl in clients if cl.get("email", "").endswith("__ios")]
        if not real_clients and not shadow_clients:
            _box_row(f"  {DIM}Пользователи не найдены.{NC}")
        else:
            if real_clients:
                _box_row(f"  {'N':<4} {'Email/имя':<30} {'UUID':<38} {'Flow':<20}")
                _box_bottom()
                print("  " + "─" * 96)
                for i, cl in enumerate(real_clients, 1):
                    print(f"  {i:<4} {cl.get('email','—'):<30} "
                          f"{cl.get('id','—'):<38} {cl.get('flow','—'):<20}")
            if shadow_clients:
                if real_clients:
                    print()
                print(f"  {DIM}iOS-shadow (служебные, без flow — для Karing):{NC}")
                print("  " + "─" * 96)
                for cl in shadow_clients:
                    print(f"  {DIM}  —   {cl.get('email','—'):<30} "
                          f"{cl.get('id','—'):<38} {cl.get('flow','—') or '—':<20}{NC}")
    except Exception:
        warn("Не удалось прочитать конфиг")
    print()


def do_user_add() -> None:
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_link   = core._box_link
    CYAN        = core.CYAN
    BOLD        = core.BOLD
    NC          = core.NC
    warn        = core.warn
    success     = core.success
    gen_uuid    = core.gen_uuid
    XTLS_FLOW   = core.XTLS_FLOW
    cfg = _users_get_config()
    print()
    print()
    _box_top(f"Добавление пользователя")
    _box_row()
    _box_row()

    # Email
    _box_bottom()
    while True:
        new_email = input(f"{CYAN}Email/имя пользователя:{NC} ").strip()
        if not new_email:
            warn("Имя не может быть пустым")
            continue
        if ' ' in new_email:
            warn("Имя не должно содержать пробелов")
            continue
        try:
            with cfg.open() as f:
                c = json.load(f)
            clients = (c.get("inbounds", [{}])[0]
                       .get("settings", {}).get("clients", []))
            if any(cl.get("email", "") == new_email for cl in clients):
                warn(f"Пользователь '{new_email}' уже существует")
                continue
        except Exception:
            pass
        break

    # UUID
    auto_uuid = gen_uuid()
    new_uuid_in = input(f"{CYAN}UUID [{auto_uuid}]:{NC} ").strip()
    new_uuid = new_uuid_in or auto_uuid
    if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', new_uuid):
        warn("Неверный UUID, используем авто")
        new_uuid = auto_uuid

    try:
        with cfg.open() as f:
            c = json.load(f)
        # Определяем протокол из конфига: xHTTP не использует flow xtls-rprx-vision
        net = (c.get("inbounds", [{}])[0]
               .get("streamSettings", {}).get("network", "tcp"))
        new_client: dict = {"id": new_uuid, "email": new_email}
        if net != "xhttp" and XTLS_FLOW:
            new_client["flow"] = XTLS_FLOW
        c["inbounds"][0]["settings"]["clients"].append(new_client)
        with cfg.open('w') as f:
            json.dump(c, f, indent=2, ensure_ascii=False)
    except Exception as e:
        warn(f"Ошибка добавления пользователя: {e}")

    success(f"Пользователь '{new_email}' добавлен")

    link = _users_gen_link(cfg, new_uuid, new_email)
    if link:
        print(f"{BOLD}VLESS ссылка:{NC}")
        _box_link(link)
        _show_qr(link, new_email, f"/root/vless_qr_{new_email}.png")
        link_file = Path(f"/root/vless_link_{new_email}.txt")
        link_file.write_text(link)
        link_file.chmod(0o600)
        success(f"Ссылка сохранена: {link_file}")
    else:
        _box_bottom()
    _users_apply_config(cfg)


def do_user_delete() -> None:
    core = _core_module()
    _box_top  = core._box_top
    _box_row  = core._box_row
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_link   = core._box_link
    CYAN        = core.CYAN
    BOLD        = core.BOLD
    NC          = core.NC
    warn        = core.warn
    success     = core.success
    die         = core.die
    cfg = _users_get_config()
    do_user_list()
    target = input(f"{CYAN}Email или UUID для удаления:{NC} ").strip()
    if not target:
        warn("Отмена")
        return

    try:
        with cfg.open() as f:
            c = json.load(f)
        clients = c["inbounds"][0]["settings"]["clients"]
        before  = len(clients)
        removed = [cl for cl in clients
                   if cl.get("email", "") == target or cl.get("id", "") == target]
        new_clients = [cl for cl in clients
                       if cl.get("email", "") != target and cl.get("id", "") != target]
        after = len(new_clients)

        if before == after:
            warn(f"Пользователь '{target}' не найден")
            return
        if after == 0:
            warn("Нельзя удалить последнего пользователя")
            return

        c["inbounds"][0]["settings"]["clients"] = new_clients
        with cfg.open('w') as f:
            json.dump(c, f, indent=2, ensure_ascii=False)

        del_email = removed[0].get("email", "") if removed else target
        success(f"Пользователь '{del_email}' удалён")
        for p in (f"/root/vless_link_{del_email}.txt",
                  f"/root/vless_qr_{del_email}.png"):
            Path(p).unlink(missing_ok=True)
        _users_apply_config(cfg)

        # ── Аддитивный блок: удаление теневого iOS-клиента ────────────────
        # Если у удаляемого юзера был создан теневой клиент (через
        # _users_get_or_create_ios_shadow для iOS-ссылки), его тоже надо
        # убрать — иначе в clients[] остаётся висеть запись `__ios` без
        # своего основного юзера, которая никому не нужна и засоряет
        # список. Идемпотентно: если shadow нет — блок no-op, поведение
        # для юзеров без iOS-варианта идентично допатчевому.
        #
        # ВАЖНО: отдельный _users_apply_config — намеренный, а не «забыли
        # объединить с вызовом выше». Удаление основного и удаление
        # shadow разделены, чтобы при сбое中途 (например JSON-ошибка при
        # повторном чтении) основной юзер уже был удалён и применён, а
        # shadow остался бы — это лучше, чем частично удалённый основной.
        try:
            shadow_email = _shadow_ios_email(del_email)
            with cfg.open() as f:
                c2 = json.load(f)
            shadow_clients = c2["inbounds"][0]["settings"]["clients"]
            if any(cl.get("email", "") == shadow_email for cl in shadow_clients):
                c2["inbounds"][0]["settings"]["clients"] = [
                    cl for cl in shadow_clients if cl.get("email", "") != shadow_email
                ]
                with cfg.open('w') as f:
                    json.dump(c2, f, indent=2, ensure_ascii=False)
                _users_apply_config(cfg)
                Path(f"/root/vless_qr_ios_{del_email}.png").unlink(missing_ok=True)
        except Exception as _shadow_e:
            # Не роняем весь do_user_delete из-за сбоя cleanup-шага —
            # основной юзер уже удалён. Логируем через warn (если доступен).
            try:
                warn(f"Предупреждение: не удалось удалить iOS-shadow для '{del_email}': {_shadow_e}")
            except Exception:
                pass
    except Exception as e:
        warn(f"Ошибка при удалении: {e}")


# do_user_show_link() и do_user_menu() удалены в патче №5.
#
# Аудит показал, что do_user_menu() — строго подмножество
# do_unified_user_manager() из _core.py: те же L/A/D/S/K/I пункты,
# но без 4-8/E (статистика/применить/метка/отключить/редактировать/экспорт).
# do_unified_user_manager() доступен из главного меню (2 → 1) и использует
# _unified_load_users/_unified_save_users, которые синхронизируют users.json
# и config.json одновременно — do_user_menu() работал только с config.json.
#
# do_user_show_link() вызывалась ТОЛЬКО из do_user_menu() (стр. 693 в старом
# коде). do_user_add() использует _users_gen_link() напрямую (не эту функцию).
# Аналогичная функциональность есть в do_unified_user_manager() пункт 3
# (вызывает _unified_show_links).
#
# Пункт K (iOS-ссылка) из do_user_menu() был уже мёртвым кодом — do_user_menu
# импортировалась в _core.py, но нигде не вызывалась. Патч №3 добавил рабочий
# пункт K в do_unified_user_manager (do_user_show_link_ios_by_uuid),
# патч №4 — в _menu_users (generate_client_links_ios).
#
# do_user_show_link_ios() (с input-ом email/uuid) оставлена — используется
# тестами и может быть полезна как CLI-точка входа.

def _users_gen_link_ios(cfg: Path, uuid_str: str, email: str) -> str:
    """iOS/Karing-совместимый вариант ссылки для конкретного пользователя.

    Обёртка над существующим _users_gen_link() + постпроцессор
    to_ios_karing_link() из ios_link_variant. НЕ дублирует логику сборки
    host/port/pbk/sid/domain — только вызывает готовую ссылку и убирает
    из неё `&flow=xtls-rprx-vision` и сырой эмодзи-флаг в начале fragment.

    Возвращает пустую строку, если базовая _users_gen_link() вернула
    пустую (т.е. ошибку чтения config.json) — поведение идентично
    оригиналу, никаких новых точек отказа.
    """
    from chimera.modules.ios_link_variant import to_ios_karing_link
    base = _users_gen_link(cfg, uuid_str, email)
    if not base:
        return ""
    return to_ios_karing_link(base)


# =============================================================================
#  Теневой iOS-клиент (без XTLS Vision flow)
# =============================================================================
# Корень проблемы, которую чинит этот блок:
#   Патч №1 (постпроцессор to_ios_karing_link) показывал пользователю REALITY-
#   ссылку БЕЗ `&flow=xtls-rprx-vision`, но серверная clients[] в config.json
#   продолжала хранить `"flow": "xtls-rprx-vision"` для этого UUID. Xray при
#   хендшейке ожидает Vision-extended ClientHello, а клиент без flow в ссылке
#   его не отправляет → гарантированный разрыв соединения.
#
#   Решение: для каждого REALITY-пользователя, которому нужна iOS-ссылка,
#   создаётся ОТДЕЛЬНЫЙ shadow-клиент в той же clients[] — БЕЗ ключа `flow`
#   в словаре. Этот shadow-клиент использует свой UUID (его видит iOS-юзер),
#   а оригинальный клиент остаётся нетронутым для Android/ПК.
#
#   На xHTTP-инбаунде flow не используется в принципе → shadow не нужен,
#   функция возвращает None, вызывающий код использует обычную ссылку.

def _shadow_ios_email(base_email: str) -> str:
    """Детерминированное имя теневого клиента. НЕ содержит пробелов.

    Суффикс `__ios` выбран так, чтобы:
      • Не конфликтовать с обычными email-адресами (никто не использует
        двойное подчёркивание в реальных ящиках).
      • Быть визуально различимым в do_user_list() — администратор видит,
        что это служебная запись для iOS-варианта конкретного юзера.
      • Детерминированно восстанавливаться по base_email —
        _shadow_ios_email("alice") == "alice__ios" всегда.
    """
    return f"{base_email}__ios"


def _users_get_or_create_ios_shadow(cfg: Path, base_email: str) -> tuple[str, str] | None:
    """
    Возвращает (shadow_uuid, shadow_email) для REALITY-юзера base_email.
    Если теневой клиент уже существует в clients[] — переиспользует его
    (идемпотентно, повторный вызов НЕ плодит дубликаты).
    Если сеть — xhttp, теневой клиент не нужен: возвращает None
    (вызывающий код должен в этом случае просто использовать обычную
    _users_gen_link на ОРИГИНАЛЬНОМ uuid юзера).
    Если base_email не найден среди clients[] — возвращает None.
    """
    core = _core_module()
    gen_uuid = core.gen_uuid
    with cfg.open() as f:
        c = json.load(f)
    inbound = c.get("inbounds", [{}])[0]
    net = inbound.get("streamSettings", {}).get("network", "tcp")
    if net == "xhttp":
        return None
    clients = inbound.get("settings", {}).get("clients", [])
    base_client = next((cl for cl in clients if cl.get("email", "") == base_email), None)
    if not base_client:
        return None
    shadow_email = _shadow_ios_email(base_email)
    existing = next((cl for cl in clients if cl.get("email", "") == shadow_email), None)
    if existing:
        return existing.get("id", ""), shadow_email
    shadow_uuid = gen_uuid()
    # ВАЖНО: ключ "flow" здесь НЕ прописывается вообще (ни пустой строкой,
    # ни отсутствующим ключом с явным None) — просто нет такого ключа в
    # словаре, ровно как Xray ожидает клиента без Vision.
    new_client = {"id": shadow_uuid, "email": shadow_email}
    clients.append(new_client)
    inbound["settings"]["clients"] = clients
    c["inbounds"][0] = inbound
    with cfg.open('w') as f:
        json.dump(c, f, indent=2, ensure_ascii=False)
    _users_apply_config(cfg)   # тот же безопасный путь, что и do_user_add()
    return shadow_uuid, shadow_email


def do_user_show_link_ios() -> None:
    """iOS/Karing-совместимая ссылка для конкретного пользователя.

    Для REALITY-режима:
      Создаёт (или переиспользует) теневой клиент в clients[] БЕЗ ключа
      `flow`, и генерирует ссылку на его UUID. Серверная clients[]
      оригинального юзера НЕ трогается — Android/ПК продолжают
      работать как раньше со своим flow=xtls-rprx-vision.

    Для xHTTP-режима:
      Shadow не нужен (flow там не используется в принципе) — ссылка
      строится на UUID оригинального юзера, to_ios_karing_link всё
      равно отрабатывает как no-op (в xHTTP нет flow ни в ссылке, ни
      в server-side client).

    QR пишется в отдельный файл /root/vless_qr_ios_{email}.png, НЕ
    перезаписывая существующий /root/vless_qr_{email}.png.
    """
    core = _core_module()
    _box_link = core._box_link
    CYAN      = core.CYAN
    BOLD      = core.BOLD
    NC        = core.NC
    DIM       = core.DIM
    warn      = core.warn
    cfg = _users_get_config()
    do_user_list()
    target = input(f"{CYAN}Email или UUID:{NC} ").strip()
    if not target:
        warn("Отмена")
        return

    try:
        with cfg.open() as f:
            c = json.load(f)
        clients = (c.get("inbounds", [{}])[0]
                   .get("settings", {}).get("clients", []))
        found = next((cl for cl in clients
                      if cl.get("email", "") == target or cl.get("id", "") == target), None)
    except Exception:
        found = None

    if not found:
        warn(f"Пользователь '{target}' не найден")
        return

    u_email = found.get("email", "")
    shadow = _users_get_or_create_ios_shadow(cfg, u_email)
    if shadow is None:
        # xHTTP-режим ИЛИ юзер не найден в clients[] (не должно случиться,
        # т.к. found уже найден выше, но на всякий случай) — используем
        # обычную ссылку без изменений, она и так iOS-совместима.
        u_uuid = found.get("id", "")
        link = _users_gen_link_ios(cfg, u_uuid, u_email)
    else:
        shadow_uuid, shadow_email = shadow
        link = _users_gen_link_ios(cfg, shadow_uuid, shadow_email)
    if link:
        print(f"{BOLD}📱 iOS/Karing-совместимая VLESS-ссылка для '{u_email}':{NC}")
        print(f"{DIM}  (без &flow=xtls-rprx-vision и без эмодзи-флага){NC}")
        _box_link(link)
        # Отдельное имя файла — не перезаписывать существующий QR.
        _show_qr(link, f"{u_email} (iOS)", f"/root/vless_qr_ios_{u_email}.png")


def do_user_show_link_ios_by_uuid(uuid_str: str) -> None:
    """iOS/Karing-совместимая ссылка по UUID — для интеграции в
    do_unified_user_manager (пункт K).

    КЛЮЧЕВОЕ ОТЛИЧИЕ от do_user_show_link_ios(): email берётся НАПРЯМУЮ
    из clients[] config.json по UUID, а не из аргумента или из
    _unified_load_users() (где email может быть рассинхронизирован с
    clients[] — users.json хранит свою копию, и пункт "8. Редактировать"
    в do_unified_user_manager мог обновить одну сторону без другой).

    Почему это важно: _users_get_or_create_ios_shadow(cfg, base_email)
    ищет клиента в clients[] по email. Если передать email из
    _unified_load_users(), а он не совпадает с тем, что в clients[] —
    функция молча вернёт None ("юзер не найден"), админ не поймёт,
    почему для конкретного человека iOS-ссылка не генерируется.

    Фолбэк: если UUID не найден в clients[] — явное предупреждение, а не
    молчаливый None.
    """
    core = _core_module()
    _box_link = core._box_link
    BOLD      = core.BOLD
    NC        = core.NC
    DIM       = core.DIM
    warn      = core.warn
    info      = core.info
    cfg = _users_get_config()

    # 1. Ищем client в config.json по UUID — это единый источник правды.
    try:
        with cfg.open() as f:
            c = json.load(f)
        clients = (c.get("inbounds", [{}])[0]
                   .get("settings", {}).get("clients", []))
        found = next((cl for cl in clients if cl.get("id", "") == uuid_str), None)
    except Exception as e:
        warn(f"Ошибка чтения config.json: {e}")
        return

    if not found:
        # Явный фолбэк: UUID есть в users.json, но в clients[] его нет —
        # значит юзер не применён (пункт "5. Применить список") либо
        # UUID был удалён из config.json вручную. iOS-ссылку дать нельзя —
        # Xray не пустит такого юзера и с оригинальной ссылкой, не только
        # с iOS. Предупреждаем явно.
        warn(f"UUID '{uuid_str[:8]}…' не найден в clients[] config.json.")
        info("Возможно, список пользователей не применён (пункт 5 в меню).")
        return

    u_email = found.get("email", "")
    if not u_email:
        # В clients[] email может отсутствовать — тогда shadow-функция не
        # сможет найти клиента по email (она именно так и ищет).
        warn(f"У клиента с UUID '{uuid_str[:8]}…' в config.json нет email.")
        info("Без email в clients[] невозможно создать iOS-shadow — "
             "он ищется по email. Добавьте email юзеру и примените список [5].")
        return

    # 2. Дальше — та же логика, что и в do_user_show_link_ios.
    shadow = _users_get_or_create_ios_shadow(cfg, u_email)
    if shadow is None:
        # xHTTP-режим — flow не используется, обычная ссылка на оригинальном
        # UUID уже iOS-совместима.
        link = _users_gen_link_ios(cfg, uuid_str, u_email)
    else:
        shadow_uuid, shadow_email = shadow
        link = _users_gen_link_ios(cfg, shadow_uuid, shadow_email)
    if link:
        print(f"{BOLD}📱 iOS/Karing-совместимая VLESS-ссылка для '{u_email}':{NC}")
        print(f"{DIM}  (без &flow=xtls-rprx-vision и без эмодзи-флага){NC}")
        _box_link(link)
        # Отдельное имя файла — не перезаписывать существующий QR.
        _show_qr(link, f"{u_email} (iOS)", f"/root/vless_qr_ios_{u_email}.png")


# do_user_menu() удалён в патче №5 — см. комментарий выше.


def _show_device_limit_info() -> None:
    """Информационный блок: ограничение доступа по устройствам."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_ok     = core._box_ok
    _box_warn   = core._box_warn
    _box_info   = core._box_info
    CYAN        = core.CYAN
    NC          = core.NC
    DIM         = core.DIM
    YELLOW      = core.YELLOW
    GREEN       = core.GREEN
    BOLD        = core.BOLD

    print()
    _box_top("Ограничение доступа по устройствам")
    _box_row()
    _box_row(f"  {BOLD}Как работает VLESS/REALITY:{NC}")
    _box_row(f"  {DIM}UUID в ссылке — это идентификатор пользователя, не устройства.{NC}")
    _box_row(f"  {DIM}Xray-core не ограничивает количество одновременных подключений{NC}")
    _box_row(f"  {DIM}с одним UUID. Ссылку можно скопировать на сколько угодно устройств.{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {YELLOW}Ограничение «одно устройство = одна ссылка»:{NC}")
    _box_row()
    _box_row(f"  {BOLD}Рекомендуемый способ — отдельный UUID на каждое устройство:{NC}")
    _box_row(f"  {DIM}Пример: создаёте 2 пользователя:{NC}")
    _box_row(f"    {CYAN}alice-iphone{NC}  {DIM}→ ссылка для iPhone{NC}")
    _box_row(f"    {CYAN}alice-macbook{NC}  {DIM}→ ссылка для MacBook{NC}")
    _box_row(f"  {DIM}Каждое устройство получает свою ссылку со своим UUID.{NC}")
    _box_row(f"  {DIM}Если одна ссылка утечёт — не затронет вторую.{NC}")
    _box_row(f"  {DIM}При удалении пользователя — отключается только его устройство.{NC}")
    _box_row()
    _box_ok("Это единственный надёжный способ в VLESS/REALITY.")
    _box_row()
    _box_sep()
    _box_row(f"  {YELLOW}Что насчёт HWID (Hardware ID)?{NC}")
    _box_row()
    _box_row(f"  {DIM}Коммерческие панели (Marzban, Hiddify Next, 3X-UI) используют{NC}")
    _box_row(f"  {DIM}кастомные форки Xray со своим proxy-слоем, который добавляет{NC}")
    _box_row(f"  {DIM}HWID-поле в handshake. Стандартный Xray-core HWID не поддерживает —{NC}")
    _box_row(f"  {DIM}VLESS-протокол просто не имеет такого поля.{NC}")
    _box_row()
    _box_row(f"  {DIM}Альтернативы, которые НЕ работают надёжно:{NC}")
    _box_row(f"  {DIM}• connlimit по IP — ломает NAT (2 устройства за роутером){NC}")
    _box_row(f"  {DIM}• Мониторинг access.log — race condition, хрупко{NC}")
    _box_row(f"  {DIM}• Блокировка по source IP — меняется при перезде/Wi-Fi смене{NC}")
    _box_row()
    _box_info(f"  {BOLD}Итог: создавайте отдельного пользователя на каждое устройство.{NC}")
    _box_bottom()
    input(f"  {CYAN}Нажмите Enter для возврата...{NC}")


# =============================================================================
#  ГЕНЕРАЦИЯ ССЫЛОК + QR
# =============================================================================
def _show_qr(link: str, label: str, png_path: str) -> None:
    """Выводит QR-код внутри рамки бокса."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_ok     = core._box_ok
    _box_warn   = core._box_warn
    CYAN        = core.CYAN
    NC          = core.NC
    _run        = core._run
    print()
    _box_top(f"QR-код [{label}]")
    _box_row(f"  {CYAN}Отсканируйте в v2rayNG / Hiddify / Nekobox:{NC}")
    _box_sep()

    qrencode = shutil.which("qrencode")
    if qrencode:
        # Выводим QR в терминал — каждая строка через _box_row
        import subprocess as _sp
        # ГОЛУБОЙ QR: используем ANSI256 foreground (цвет модулей) через
        # --foreground / --background если qrencode >= 4.1, иначе оборачиваем
        # строки вывода в ANSI-escape для голубого цвета.
        _QR_COLOR = "\033[96m"   # bright cyan (ANSI 96)
        _QR_RESET = "\033[0m"
        try:
            _qr_proc = _sp.run(
                [qrencode, "-t", "ANSIUTF8", "-m", "1",
                 "--foreground=00BFFF", "--background=000000",
                 "--strict-version", link],
                capture_output=True, text=True
            )
            _qr_lines = _qr_proc.stdout.splitlines()
        except Exception:
            _qr_lines = []
        if not _qr_lines:
            # fallback: пробуем без --foreground (старые версии qrencode)
            try:
                _qr_proc = _sp.run(
                    [qrencode, "-t", "ANSIUTF8", "-m", "1", link],
                    capture_output=True, text=True
                )
                _qr_lines = _qr_proc.stdout.splitlines()
            except Exception:
                _qr_lines = []
        for _ql in _qr_lines:
            # Вставляем QR-строку внутрь рамки с отступом.
            # Если qrencode не поддержал --foreground, оборачиваем в CYAN escape.
            if _QR_COLOR not in _ql and "\033[" not in _ql:
                _box_row(f"  {_QR_COLOR}{_ql}{_QR_RESET}")
            else:
                _box_row(f"  {_ql}")
        # Сохраняем PNG
        r = _run([qrencode, "-t", "PNG", "-o", png_path, "-s", "8", "-m", "4", link],
                 check=False, quiet=True)
        _box_sep()
        if r.returncode == 0:
            _box_ok(f"QR PNG сохранён: {png_path}")
        else:
            _box_warn(f"Не удалось сохранить QR PNG: {png_path}")
    else:
        # Fallback: python3-qrcode
        try:
            import qrcode  # type: ignore
            import io as _io
            qr = qrcode.QRCode(border=1)
            qr.add_data(link)
            qr.make(fit=True)
            # Захватываем ASCII-вывод
            _buf = _io.StringIO()
            import sys as _sys
            _old_stdout = _sys.stdout
            _sys.stdout = _buf
            qr.print_ascii(invert=True)
            _sys.stdout = _old_stdout
            _QR_COLOR = "\033[96m"
            _QR_RESET = "\033[0m"
            for _ql in _buf.getvalue().splitlines():
                _box_row(f"  {_QR_COLOR}{_ql}{_QR_RESET}")
            img = qr.make_image(fill_color='#00BFFF', back_color='black')
            img.save(png_path)
            _box_sep()
            _box_ok(f"QR PNG сохранён: {png_path}")
        except ImportError:
            _box_warn("python3-qrcode не установлен: pip3 install qrcode[pil]")
        except Exception as e:
            _box_warn(f"Ошибка QR: {e}")

    _box_bottom()


def _gen_vless_link(host: str, uuid_str: str, pbk: str,
                    sid: str, domain: str, fp: str = "chrome",
                    proto: str = "reality",
                    xhttp_path: str = "/", xhttp_mode: str = "stream-up",
                    port: int = 443) -> str:
    """Генерирует VLESS-ссылку для REALITY или xHTTP TLS.

    При активном профиле CDN masking (core.XHTTP_CDN_MASKING=True) добавляет
    параметр `host=` в URL — он соответствует xhttpSettings.host, нужен для
    маскировки под реальный HTTPS-запрос через CDN.
    """
    core = _core_module()
    get_server_country_cached = core.get_server_country_cached
    import urllib.parse
    _, _, _flag = get_server_country_cached()
    _flag_prefix = f"{_flag} " if _flag and _flag != "🌐" else ""
    label = _flag_prefix + urllib.parse.quote(domain)
    if proto == "xhttp":
        path_enc = urllib.parse.quote(xhttp_path, safe="/")
        _extra_query = ""
        # CDN masking: добавляем host= параметр для XHTTP-маскировки.
        # Значение берётся из CDN_MASKING_HOST (или domain если пусто).
        if getattr(core, "XHTTP_CDN_MASKING", False):
            try:
                from chimera.modules.xhttp_cdn_masking import CDN_MASKING_HOST
                _host_param = CDN_MASKING_HOST or domain
                _extra_query = f"&host={urllib.parse.quote(_host_param, safe='')}"
            except ImportError:
                pass  # fallback: обычная ссылка без host=
        return (f"vless://{uuid_str}@{host}:{port}"
                f"?type=xhttp&security=tls&sni={domain}"
                f"&path={path_enc}&mode={xhttp_mode}"
                f"&fp={fp}{_extra_query}#{label}")
    else:
        return (f"vless://{uuid_str}@{host}:{port}"
                f"?type=tcp&security=reality&pbk={pbk}"
                f"&fp={fp}&sni={domain}&sid={sid}"
                f"&flow=xtls-rprx-vision#{label}")


def generate_client_links() -> None:
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_link   = core._box_link
    _box_wrap_msg = core._box_wrap_msg
    _get_box_width = core._get_box_width
    get_server_ip  = core.get_server_ip
    PARAM_FINGERPRINT = core.PARAM_FINGERPRINT
    PROTOCOL_MODE     = core.PROTOCOL_MODE
    PARAM_REALITY_DEST = core.PARAM_REALITY_DEST
    AWG_EXIT_ENABLED  = core.AWG_EXIT_ENABLED
    PARAM_DOMAIN      = core.PARAM_DOMAIN
    PARAM_UUID        = core.PARAM_UUID
    PARAM_PUBLIC_KEY  = core.PARAM_PUBLIC_KEY
    PARAM_SHORTID     = core.PARAM_SHORTID
    XHTTP_PATH        = core.XHTTP_PATH
    XHTTP_MODE        = core.XHTTP_MODE
    SERVER_PORT       = core.SERVER_PORT
    IS_IPV6_AVAILABLE = core.IS_IPV6_AVAILABLE
    GREEN   = core.GREEN
    CYAN    = core.CYAN
    MAGENTA = core.MAGENTA
    BLUE    = core.BLUE
    DIM     = core.DIM
    NC      = core.NC

    _BOX_W = _get_box_width()
    setattr(core, "_BOX_W", _BOX_W)
    print()
    print()
    _box_top(f"Ссылки для подключения")
    _box_row()
    fp = PARAM_FINGERPRINT or "chrome"
    proto = PROTOCOL_MODE  # "reality" или "xhttp"
    # При AWG SNI = домен маскировки, при обычном REALITY SNI = собственный домен
    _sni = PARAM_REALITY_DEST if (AWG_EXIT_ENABLED and PARAM_REALITY_DEST) else PARAM_DOMAIN

    ipv4 = get_server_ip("4")
    if ipv4:
        link4 = _gen_vless_link(
            ipv4, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_SHORTID, _sni, fp,
            proto=proto, xhttp_path=XHTTP_PATH, xhttp_mode=XHTTP_MODE,
            port=SERVER_PORT,
        )
        print()
        print(f"{GREEN}📡 IPv4 ссылка:{NC}")
        _box_link(link4)
        link_file = Path("/root/vless_link.txt")
        link_file.write_text(link4)
        link_file.chmod(0o600)
        print()
        _show_qr(link4, "IPv4", "/root/vless_qr_ipv4.png")

    # BUGFIX: IPV6_PREFLIGHT — это первый global-scope адрес из `ip -6 addr
    # show`, определённый один раз при установке, без подтверждения, что
    # именно ОН виден снаружи (при нескольких global IPv6 — privacy-адреса
    # RFC4941, доп. интерфейсы от WARP/AWG — порядок в выводе `ip addr` не
    # гарантирован). IPv4-ссылка рядом уже строится через get_server_ip("4")
    # с внешней проверкой (curl api4.ipify.org) — используем ту же логику
    # для IPv6, вместо непроверенного локального адреса.
    ipv6_ext = get_server_ip("6") if IS_IPV6_AVAILABLE else ""
    if ipv6_ext:
        link6 = _gen_vless_link(
            f"[{ipv6_ext}]", PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_SHORTID, _sni, fp,
            proto=proto, xhttp_path=XHTTP_PATH, xhttp_mode=XHTTP_MODE,
            port=SERVER_PORT,
        )
        print()
        print(f"{CYAN}🌐 IPv6 ссылка:{NC}")
        _box_link(link6)
        link6_file = Path("/root/vless_link_ipv6.txt")
        link6_file.write_text(link6)
        link6_file.chmod(0o600)
        print()
        _show_qr(link6, "IPv6", "/root/vless_qr_ipv6.png")

    link_ds = _gen_vless_link(
        PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_SHORTID, _sni, fp,
        proto=proto, xhttp_path=XHTTP_PATH, xhttp_mode=XHTTP_MODE,
        port=SERVER_PORT,
    )
    print()
    print(f"{MAGENTA}🔄 Domain (DualStack) ссылка:{NC}")
    _box_link(link_ds)
    print()
    _show_qr(link_ds, "Domain/DualStack", "/root/vless_qr.png")
    print()

    _box_row()
    proto_label = f"xHTTP TLS ({XHTTP_MODE})" if proto == "xhttp" else "VLESS+REALITY"
    _box_row(f"{BLUE}💡 Протокол: {proto_label}{NC}")
    _box_row(f"{BLUE}💡 Совет:{NC} Отсканируйте QR в v2rayNG, Hiddify, FoXray, Nekobox")
    _box_wrap_msg(f"   {DIM}Файлы QR:{NC} ", 12, "/root/vless_qr.png  /root/vless_qr_ipv4.png  /root/vless_qr_ipv6.png")
    _box_row()
    from chimera.modules.box_renderer import _print_link_warning
    _print_link_warning(is_vless=True)
    _box_bottom()


def generate_client_links_ios() -> None:
    """iOS/Karing-совместимые сводные ссылки (IPv4/IPv6/Domain).

    Копия структуры generate_client_links(), но:
      • Для REALITY: создаёт/переиспользует shadow-клиент без flow
        (_users_get_or_create_ios_shadow) и строит ссылки на его UUID.
        Email резолвится из живого clients[] по PARAM_UUID (та же защита
        от рассинхрона, что в do_user_show_link_ios_by_uuid) — не из
        state.json напрямую.
      • Для xHTTP: shadow не нужен (flow не используется), ссылки
        строятся на PARAM_UUID, to_ios_karing_link отрабатывает как
        no-op (в xHTTP нет flow ни в ссылке, ни в server-side client).
      • Каждая ссылка прогоняется через to_ios_karing_link() (полный
        no-op для shadow-варианта, потому что shadow-клиент уже без flow
        — но сохраняем для единообразия и для эмодзи-флага).
      • Файлы и QR-картинки пишутся в ОТДЕЛЬНЫЕ имена (суффикс _ios),
        чтобы НЕ перезаписывать существующие /root/vless_link*.txt и
        /root/vless_qr_*.png от generate_client_links().

    Существующая generate_client_links() НЕ трогается.

    Мутирует _BOX_W по той же схеме — dual-form паттерн проекта.
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_link   = core._box_link
    _box_wrap_msg = core._box_wrap_msg
    _box_warn   = core._box_warn
    _get_box_width = core._get_box_width
    get_server_ip  = core.get_server_ip
    PARAM_FINGERPRINT = core.PARAM_FINGERPRINT
    PROTOCOL_MODE     = core.PROTOCOL_MODE
    PARAM_REALITY_DEST = core.PARAM_REALITY_DEST
    AWG_EXIT_ENABLED  = core.AWG_EXIT_ENABLED
    PARAM_DOMAIN      = core.PARAM_DOMAIN
    PARAM_UUID        = core.PARAM_UUID
    PARAM_PUBLIC_KEY  = core.PARAM_PUBLIC_KEY
    PARAM_SHORTID     = core.PARAM_SHORTID
    XHTTP_PATH        = core.XHTTP_PATH
    XHTTP_MODE        = core.XHTTP_MODE
    SERVER_PORT       = core.SERVER_PORT
    IS_IPV6_AVAILABLE = core.IS_IPV6_AVAILABLE
    GREEN   = core.GREEN
    CYAN    = core.CYAN
    MAGENTA = core.MAGENTA
    BLUE    = core.BLUE
    DIM     = core.DIM
    NC      = core.NC
    warn    = core.warn

    from chimera.modules.ios_link_variant import to_ios_karing_link

    _BOX_W = _get_box_width()
    setattr(core, "_BOX_W", _BOX_W)
    print()
    print()
    _box_top(f"📱 iOS/Karing-совместимые ссылки")
    _box_row()
    _box_row(f"  {DIM}flow=xtls-rprx-vision и эмодзи-флаг убраны{NC}")
    _box_row()
    fp = PARAM_FINGERPRINT or "chrome"
    proto = PROTOCOL_MODE  # "reality" или "xhttp"
    _sni = PARAM_REALITY_DEST if (AWG_EXIT_ENABLED and PARAM_REALITY_DEST) else PARAM_DOMAIN

    # ── Резолвим email и UUID для генерации ссылок ────────────────────────
    # Для REALITY: shadow-клиент (без flow), UUID берётся из него.
    # Для xHTTP: оригинальный PARAM_UUID, shadow не нужен.
    # Email — из живого clients[] по PARAM_UUID (защита от рассинхрона
    # state.json ↔ clients[], та же логика, что в do_user_show_link_ios_by_uuid).
    link_uuid = PARAM_UUID
    link_email = ""
    if proto == "reality":
        cfg = _users_get_config()
        try:
            with cfg.open() as f:
                c = json.load(f)
            clients = (c.get("inbounds", [{}])[0]
                       .get("settings", {}).get("clients", []))
            base_client = next((cl for cl in clients if cl.get("id", "") == PARAM_UUID), None)
            if not base_client:
                warn(f"PARAM_UUID '{PARAM_UUID[:8]}…' не найден в clients[] config.json.")
                _box_warn("Возможно, список пользователей не применён. "
                          "Ссылки будут с оригинальным UUID (могут не работать на iOS без shadow).")
            else:
                base_email = base_client.get("email", "")
                if not base_email:
                    warn("У root-юзера в clients[] пустой email — "
                         "невозможно создать iOS-shadow.")
                    _box_warn("Ссылки будут с оригинальным UUID (могут не работать на iOS).")
                else:
                    shadow = _users_get_or_create_ios_shadow(cfg, base_email)
                    if shadow is not None:
                        link_uuid, link_email = shadow
                    # если shadow вернул None при proto == "reality" —
                    # это ненормально (xhttp-инбаунд не должен быть reality),
                    # но не роняем — fallback на PARAM_UUID.
        except Exception as e:
            warn(f"Ошибка чтения config.json для shadow: {e}")
            _box_warn("Ссылки будут с оригинальным UUID (могут не работать на iOS).")

    ipv4 = get_server_ip("4")
    if ipv4:
        link4 = _gen_vless_link(
            ipv4, link_uuid, PARAM_PUBLIC_KEY, PARAM_SHORTID, _sni, fp,
            proto=proto, xhttp_path=XHTTP_PATH, xhttp_mode=XHTTP_MODE,
            port=SERVER_PORT,
        )
        link4 = to_ios_karing_link(link4)
        print()
        print(f"{GREEN}📡 IPv4 ссылка (iOS):{NC}")
        _box_link(link4)
        link_file = Path("/root/vless_link_ios.txt")
        link_file.write_text(link4)
        link_file.chmod(0o600)
        print()
        _show_qr(link4, "IPv4 (iOS)", "/root/vless_qr_ipv4_ios.png")

    ipv6_ext = get_server_ip("6") if IS_IPV6_AVAILABLE else ""
    if ipv6_ext:
        link6 = _gen_vless_link(
            f"[{ipv6_ext}]", link_uuid, PARAM_PUBLIC_KEY, PARAM_SHORTID, _sni, fp,
            proto=proto, xhttp_path=XHTTP_PATH, xhttp_mode=XHTTP_MODE,
            port=SERVER_PORT,
        )
        link6 = to_ios_karing_link(link6)
        print()
        print(f"{CYAN}🌐 IPv6 ссылка (iOS):{NC}")
        _box_link(link6)
        link6_file = Path("/root/vless_link_ipv6_ios.txt")
        link6_file.write_text(link6)
        link6_file.chmod(0o600)
        print()
        _show_qr(link6, "IPv6 (iOS)", "/root/vless_qr_ipv6_ios.png")

    if PARAM_DOMAIN:
        link_ds = _gen_vless_link(
            PARAM_DOMAIN, link_uuid, PARAM_PUBLIC_KEY, PARAM_SHORTID, _sni, fp,
            proto=proto, xhttp_path=XHTTP_PATH, xhttp_mode=XHTTP_MODE,
            port=SERVER_PORT,
        )
        link_ds = to_ios_karing_link(link_ds)
        print()
        print(f"{MAGENTA}🔄 Domain (DualStack) ссылка (iOS):{NC}")
        _box_link(link_ds)
        print()
        _show_qr(link_ds, "Domain/DualStack (iOS)", "/root/vless_qr_ios.png")
        print()

    _box_row()
    proto_label = f"xHTTP TLS ({XHTTP_MODE})" if proto == "xhttp" else "VLESS+REALITY"
    _box_row(f"{BLUE}💡 Протокол: {proto_label} | Порт: {SERVER_PORT}{NC}")
    _box_row(f"{BLUE}💡 Совет:{NC} Импортируйте в Karing (iOS) или Hiddify (iOS)")
    _box_wrap_msg(f"   {DIM}Файлы QR:{NC} ", 12,
                  "/root/vless_qr_ios.png  /root/vless_qr_ipv4_ios.png  /root/vless_qr_ipv6_ios.png")
    _box_row()
    from chimera.modules.box_renderer import _print_link_warning
    _print_link_warning(is_vless=True)
    _box_bottom()


# =============================================================================
#  Region B — ЕДИНЫЙ МЕНЕДЖЕР ПОЛЬЗОВАТЕЛЕЙ (users.json + xray config.json)
# =============================================================================
def _users_load() -> list[dict]:
    """Загружает список пользователей из users.json."""
    core = _core_module()
    USERS_FILE  = core.USERS_FILE
    STATE_FILE  = core.STATE_FILE
    if not USERS_FILE.exists():
        # Инициализируем из текущего PARAM_UUID если есть
        default = []
        if STATE_FILE.exists():
            try:
                st = json.loads(STATE_FILE.read_text())
                if st.get("uuid"):
                    default = [{
                        "uuid":    st["uuid"],
                        "email":   st.get("email", "default@xray"),
                        "name":    "default",
                        "created": st.get("installed_at", ""),
                    }]
            except Exception:
                pass
        return default
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return []


def _users_save(users: list[dict]) -> None:
    core = _core_module()
    USERS_FILE = core.USERS_FILE
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))
    USERS_FILE.chmod(0o640)


def _users_patch_config_no_restart(users: list[dict]) -> bool:
    """
    Вписывает пользователей в inbound config.json БЕЗ перезапуска Xray.
    Используется внутри _apply_split_tunnel_config_from_state и аналогичных
    функций, где рестарт выполняется явно после всех патчей конфига.
    """
    core = _core_module()
    CONFIG_DIR         = core.CONFIG_DIR
    XTLS_FLOW          = core.XTLS_FLOW
    _set_config_owner  = core._set_config_owner
    warn               = core.warn
    written: set = set()
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            changed = False
            for inb in cfg.get("inbounds", []):
                settings = inb.get("settings", {})
                if "clients" not in settings:
                    continue
                proto = inb.get("protocol", "")
                st    = inb.get("streamSettings", {})
                use_flow = (proto == "vless" and "realitySettings" in st)
                clients = []
                for u in users:
                    client: dict = {"id": u["uuid"]}
                    if u.get("email"):
                        client["email"] = u["email"]
                    if use_flow and XTLS_FLOW:
                        client["flow"] = XTLS_FLOW
                    clients.append(client)
                settings["clients"] = clients
                changed = True
            if changed:
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                _set_config_owner(cfg_path)
        except Exception as e:
            warn(f"Ошибка патча пользователей в {cfg_path}: {e}")
            return False
    return True


def _users_apply_to_config(users: list[dict]) -> bool:
    """
    Вписывает всех пользователей в inbound config.json и перезапускает Xray.
    Работает для REALITY (clients) и xHTTP (clients).
    Основной конфиг — CONFIG_DIR/config.json; /usr/local/etc/xray/config.json
    в режиме B является симлинком и пишется автоматически через него.

    БЕЗОПАСНОСТЬ: конфиг перезаписывается ТОЛЬКО после успешной валидации.
    Если валидация падает — оригинальный конфиг не трогается.
    """
    core = _core_module()
    CONFIG_DIR         = core.CONFIG_DIR
    XTLS_FLOW          = core.XTLS_FLOW
    XRAY_BIN           = core.XRAY_BIN
    _set_config_owner  = core._set_config_owner
    _run               = core._run
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    warn               = core.warn
    _PLACEHOLDER_UUID = "00000000-0000-0000-0000-000000000000"
    active_users = [u for u in users if not u.get("disabled")]
    effective_users = active_users if active_users else [{"uuid": _PLACEHOLDER_UUID, "email": "disabled@placeholder"}]

    # ── ДЕДУПЛИКАЦИЯ: убираем дубликаты по UUID и по email ──────────────
    # Xray падает с "User X already exists" если в clients есть два
    # пользователя с одинаковым email (даже если UUID разные).
    seen_uuids: set = set()
    seen_emails: set = set()
    deduped_users: list[dict] = []
    for u in effective_users:
        uid = u.get("uuid", "")
        email = u.get("email", "")
        if uid in seen_uuids:
            continue
        if email and email in seen_emails:
            continue
        seen_uuids.add(uid)
        seen_emails.add(email)
        deduped_users.append(u)
    if len(deduped_users) < len(effective_users):
        warn(f"Удалено дубликатов: {len(effective_users) - len(deduped_users)} "
             f"(по UUID или email)")
    effective_users = deduped_users

    # ── НАЙТИ конфиг для записи ──────────────────────────────────────────
    written: set = set()
    cfg_paths_to_write: list[Path] = []
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        cfg_paths_to_write.append(cfg_path)

    if not cfg_paths_to_write:
        warn("Конфиг Xray не найден — не могу применить пользователей")
        return False

    # ── ПОДГОТОВИТЬ новый конфиг (в памяти, БЕЗ записи на диск) ──────────
    # Строим обновлённые конфиги для каждого пути, но не записываем.
    pending_writes: list[tuple[Path, str]] = []  # (path, new_content)
    for cfg_path in cfg_paths_to_write:
        try:
            cfg = json.loads(cfg_path.read_text())
            changed = False
            for inb in cfg.get("inbounds", []):
                settings = inb.get("settings", {})
                if "clients" not in settings:
                    continue
                proto = inb.get("protocol", "")
                st    = inb.get("streamSettings", {})
                use_flow = (proto == "vless" and "realitySettings" in st)
                clients = []
                for u in effective_users:
                    client: dict = {"id": u["uuid"]}
                    if u.get("email"):
                        client["email"] = u["email"]
                    if use_flow and XTLS_FLOW:
                        client["flow"] = XTLS_FLOW
                    clients.append(client)
                settings["clients"] = clients
                changed = True
            if changed:
                new_content = json.dumps(cfg, indent=2, ensure_ascii=False)
                pending_writes.append((cfg_path, new_content))
        except Exception as e:
            warn(f"Ошибка подготовки {cfg_path}: {e}")
            return False

    if not pending_writes:
        warn("Не найдено inbound с clients — конфиг не изменён")
        return False

    # ── ВАЛИДАЦИЯ: проверить новый конфиг БЕЗ записи на диск ────────────
    # Записываем во временный файл, валидируем, удаляем.
    import tempfile
    cfg_to_test = str(cfg_paths_to_write[0])
    tmp_path = None
    try:
        # Записываем первый обновлённый конфиг во временный файл для валидации.
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(pending_writes[0][1])
            tmp_path = f.name
        val = _run([str(XRAY_BIN), "run", "-test", "-config", tmp_path],
                   capture=True, check=False, quiet=True)
    except Exception as e:
        warn(f"Ошибка валидации: {e}")
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)
        return False
    finally:
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)

    if val.returncode != 0:
        warn("Конфиг невалиден — пользователи не применены!")
        warn("Оригинальный конфиг НЕ изменён.")
        warn((val.stdout + val.stderr)[:300])
        return False

    # ── ЗАПИСЬ: валидация прошла — записываем все конфиги ───────────────
    for cfg_path, new_content in pending_writes:
        try:
            cfg_path.write_text(new_content)
            _set_config_owner(cfg_path)
        except Exception as e:
            warn(f"Ошибка записи {cfg_path}: {e}")
            return False

    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    _nginx_restart_if_reality()
    time.sleep(2)
    r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if r.stdout.strip() != "active":
        warn("Xray не запустился после обновления пользователей!")
        r_jnl = _run(["journalctl", "-u", "xray", "-n", "15", "--no-pager"],
                     capture=True, check=False, quiet=True)
        if r_jnl.stdout.strip():
            print(r_jnl.stdout.strip())
        return False
    return True


def _unified_load_users() -> list[dict]:
    """
    Загружает пользователей из обоих источников и объединяет их в единый список.
    Режим A: читает clients из xray config.json.
    Режим B: читает из users.json.
    Дедупликация по UUID.
    """
    core = _core_module()
    USERS_FILE = core.USERS_FILE
    seen_uuids: set[str] = set()
    merged: list[dict] = []

    # Источник 1: users.json (режим B)
    if USERS_FILE.exists():
        try:
            for u in json.loads(USERS_FILE.read_text()):
                uid = u.get("uuid", "")
                if uid and uid not in seen_uuids:
                    seen_uuids.add(uid)
                    entry: dict = {
                        "uuid":         uid,
                        "email":        u.get("email", f"{u.get('name','user')}@xray"),
                        "name":         u.get("name", u.get("email", "user")),
                        "created":      u.get("created", ""),
                        "source":       u.get("source", "B"),
                        "device_label": u.get("device_label", ""),
                    }
                    # Сохраняем флаг отключения — без него статус всегда [акт]
                    if u.get("disabled"):
                        entry["disabled"]    = True
                        entry["disabled_at"] = u.get("disabled_at", "")
                    merged.append(entry)
        except Exception:
            pass

    # Источник 2: xray config.json (режим A — clients inbound)
    for cfg_path in (Path("/etc/xray/config.json"),
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            clients = (cfg.get("inbounds", [{}])[0]
                       .get("settings", {}).get("clients", []))
            for cl in clients:
                uid = cl.get("id", "")
                if uid and uid not in seen_uuids:
                    seen_uuids.add(uid)
                    email = cl.get("email", "")
                    # Помечаем shadow-клиентов (созданных через
                    # _users_get_or_create_ios_shadow) полем is_ios_shadow.
                    # Не исключаем из списка — do_unified_user_manager
                    # продолжит их показывать (админ может удалить вручную
                    # при отладке). Счётчики/статус-панель фильтруют по
                    # этому полю, чтобы не задваивать «число пользователей».
                    entry = {
                        "uuid":    uid,
                        "email":   email,
                        "name":    email.split("@")[0] if email else uid[:8],
                        "created": "",
                        "source":  "A",
                        "flow":    cl.get("flow", ""),
                    }
                    if email.endswith("__ios"):
                        entry["is_ios_shadow"] = True
                    merged.append(entry)
        except Exception:
            pass
        break  # только первый найденный конфиг

    return merged


def _unified_save_users(users: list[dict]) -> None:
    """
    Сохраняет список пользователей в обоих форматах одновременно:
    — users.json (для режимов A и B)
    — xray config.json inbound clients (все реальные копии конфига)
    Симлинки пропускаются — записываем только в реальные файлы.
    """
    core = _core_module()
    CONFIG_DIR         = core.CONFIG_DIR
    XTLS_FLOW          = core.XTLS_FLOW
    _set_config_owner  = core._set_config_owner
    warn               = core.warn
    # Сохраняем в users.json — включая device_label, source и флаг отключения
    _save_list = []
    for u in users:
        rec = {
            "uuid":         u["uuid"],
            "email":        u["email"],
            "name":         u.get("name", u["email"].split("@")[0]),
            "created":      u.get("created", datetime.now(timezone.utc).isoformat()),
            "source":       u.get("source", "A"),
            "device_label": u.get("device_label", ""),
        }
        if u.get("disabled"):
            rec["disabled"]    = True
            rec["disabled_at"] = u.get("disabled_at", "")
        _save_list.append(rec)
    _users_save(_save_list)

    # Синхронизируем в xray config.json.
    # Основной конфиг — CONFIG_DIR/config.json (/etc/xray/config.json),
    # /usr/local/etc/xray/config.json часто является симлинком на него.
    cfg_paths = [CONFIG_DIR / "config.json",
                 Path("/usr/local/etc/xray/config.json")]
    written: set = set()
    for cfg_path in cfg_paths:
        if not cfg_path.exists():
            continue
        # Разрешаем симлинк и пишем только в реальный файл один раз
        try:
            real = cfg_path.resolve()
        except Exception:
            real = cfg_path
        if str(real) in written:
            continue
        written.add(str(real))
        try:
            cfg = json.loads(cfg_path.read_text())
            changed = False
            for inb in cfg.get("inbounds", []):
                settings = inb.get("settings", {})
                if "clients" not in settings:
                    continue
                proto    = inb.get("protocol", "")
                st       = inb.get("streamSettings", {})
                use_flow = (proto == "vless" and "realitySettings" in st)
                net      = st.get("network", "tcp")
                clients  = []
                for u in users:
                    cl: dict = {"id": u["uuid"]}
                    if u.get("email"):
                        cl["email"] = u["email"]
                    if (use_flow or net not in ("xhttp",)) and XTLS_FLOW:
                        cl["flow"] = XTLS_FLOW
                    clients.append(cl)
                settings["clients"] = clients
                changed = True
            if changed:
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                _set_config_owner(cfg_path)
        except Exception as e:
            warn(f"Ошибка синхронизации {cfg_path}: {e}")


def _unified_show_links(u: dict, print_output: bool = True) -> list:
    """
    Генерирует и (опционально) выводит все ссылки для пользователя:
    IPv4, IPv6 (если доступен), Domain/DualStack.
    Читает параметры из state.json — работает для старых и новых установок.
    Возвращает список сгенерированных ссылок.
    """
    core = _core_module()
    STATE_FILE  = core.STATE_FILE
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_link   = core._box_link
    get_server_ip          = core.get_server_ip
    get_server_country_cached = core.get_server_country_cached
    warn                   = core.warn
    GREEN   = core.GREEN
    CYAN    = core.CYAN
    MAGENTA = core.MAGENTA
    BLUE    = core.BLUE
    DIM     = core.DIM
    NC      = core.NC
    import urllib.parse

    if not STATE_FILE.exists():
        if print_output:
            warn("state.json не найден — сначала выполните установку")
        return []

    try:
        st = json.loads(STATE_FILE.read_text())
    except Exception as e:
        if print_output:
            warn(f"Не удалось прочитать state.json: {e}")
        return []

    domain     = st.get("domain", "")
    port       = st.get("server_port", 443)
    proto      = st.get("protocol_mode", "reality")
    pub_key    = st.get("public_key", "")
    short_id   = st.get("short_id", "")
    spiderx    = st.get("spiderx", "/")
    xhttp_path = st.get("xhttp_path", "/")
    xhttp_mode = st.get("xhttp_mode", "stream-up")
    ipv6       = st.get("ipv6", "")          # сохранённый IPv6 из state.json
    install_mode = st.get("install_mode", "A")
    # SNI: при Mode B + AWG используем reality_dest (домен маскировки),
    # во всех остальных случаях — собственный домен.
    _awg_exit    = st.get("awg_exit_enabled", False) and install_mode == "B"
    _reality_dest = st.get("reality_dest", "")
    if proto == "reality" and _awg_exit and _reality_dest:
        _sni = _reality_dest
    else:
        _sni = domain

    uid   = u["uuid"]
    label = u.get("name") or u.get("email") or "user"
    name_safe = label.replace(" ", "_").replace("/", "_")

    ipv4 = get_server_ip("4") or ""
    # IPv6: сначала из state, потом живой запрос
    if not ipv6:
        ipv6 = get_server_ip("6") or ""

    links = []

    def _mk(host: str) -> str:
        _, _, _flag = get_server_country_cached()
        _flag_prefix = f"{_flag} " if _flag and _flag != "🌐" else ""
        flagged_label = _flag_prefix + urllib.parse.quote(label)
        flagged_domain = _flag_prefix + urllib.parse.quote(domain)
        return _gen_vless_link(
            host, uid, pub_key, short_id, _sni, st.get("fingerprint", "chrome") or "chrome",
            proto=proto, xhttp_path=xhttp_path, xhttp_mode=xhttp_mode,
            port=port,
        ).replace(f"#{flagged_domain}", f"#{flagged_label}")

    if print_output:
        print()
        print()
        _box_top(f"Ссылки для {label}")
        _box_row()

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    if ipv4:
        link4 = _mk(ipv4)
        links.append(link4)
        if print_output:
            print()
            print(f"{GREEN}📡 IPv4 ссылка:{NC}")
            _box_link(link4)
            print()
            qr4 = f"/root/vless_qr_{name_safe}_ipv4.png"
            _show_qr(link4, f"{label} IPv4", qr4)
            Path(f"/root/vless_link_{name_safe}.txt").write_text(link4)
            Path(f"/root/vless_link_{name_safe}.txt").chmod(0o600)

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    if ipv6 and install_mode == "A":
        link6 = _mk(f"[{ipv6}]")
        links.append(link6)
        if print_output:
            print()
            print(f"{CYAN}🌐 IPv6 ссылка:{NC}")
            _box_link(link6)
            print()
            qr6 = f"/root/vless_qr_{name_safe}_ipv6.png"
            _show_qr(link6, f"{label} IPv6", qr6)

    # ── Domain / DualStack ────────────────────────────────────────────────────
    if domain:
        link_ds = _mk(domain)
        links.append(link_ds)
        if print_output:
            print()
            print(f"{MAGENTA}🔄 Domain (DualStack) ссылка:{NC}")
            _box_link(link_ds)
            print()
            qr_ds = f"/root/vless_qr_{name_safe}_domain.png"
            _show_qr(link_ds, f"{label} Domain", qr_ds)

    if print_output:
        _box_row()
        proto_label = f"xHTTP TLS ({xhttp_mode})" if proto == "xhttp" else "VLESS+REALITY"
        _box_row(f"{BLUE}💡 Протокол: {proto_label} | Порт: {port}{NC}")
        if not ipv6 and install_mode == "A":
            _box_row(f"   {DIM}IPv6 не обнаружен — ссылка IPv6 недоступна{NC}")
        _box_row()
        _box_bottom()

        # ── CDN masking: предупреждение рядом с vless://-ссылкой ──────────
        # Пользователь может зайти за ссылкой отдельно, много позже установки
        # — и не увидеть однократное предупреждение из run_cdn_masking_install().
        # Поэтому дублируем здесь, рядом с самой ссылкой.
        if st.get("xhttp_cdn_masking", False):
            _box_warn_y = getattr(core, "_box_warn", None) or (lambda *a, **kw: None)
            _box_top_y  = getattr(core, "_box_top", None) or (lambda *a, **kw: None)
            _box_row_y  = getattr(core, "_box_row", None) or (lambda *a, **kw: None)
            _box_sep_y  = getattr(core, "_box_sep", None) or (lambda *a, **kw: None)
            _box_bot_y  = getattr(core, "_box_bottom", None) or (lambda *a, **kw: None)
            YELLOW_Y = getattr(core, "YELLOW", "")
            BOLD_Y   = getattr(core, "BOLD", "")
            CYAN_Y   = getattr(core, "CYAN", "")
            NC_Y     = getattr(core, "NC", "")
            print()
            _box_top_y("⚠️  CDN MASKING: vless:// НЕДОСТАТОЧНО!")
            _box_row_y()
            _box_warn_y(f"{YELLOW_Y}Для профиля CDN masking обычная vless://-ссылка НЕДОСТАТОЧНА!{NC_Y}")
            _box_row_y()
            _box_row_y(f"  Экспертные параметры (xPaddingBytes, seqKey,")
            _box_row_y(f"  sessionIDKey, xmux и т.д.) не кодируются в URI —")
            _box_row_y(f"  они доступны только через sing-box JSON конфиг.")
            _box_row_y()
            _box_row_y(f"  {BOLD_Y}Используйте:{NC_Y} меню 2 → {CYAN_Y}«Экспорт для sing-box»{NC_Y}")
            _box_row_y(f"  Файл: /root/xray-client-configs/sing-box.json")
            _box_row_y()
            _box_warn_y(f"{YELLOW_Y}Без sing-box JSON маскировка не сработает.{NC_Y}")
            _box_bot_y()

    return links


def _do_user_stats_screen(install_mode: str) -> None:
    """Показывает расширенную статистику по всем пользователям."""
    core = _core_module()
    STATE_FILE  = core.STATE_FILE
    XRAY_BIN    = core.XRAY_BIN
    XRAY_STATS_API_PORT = core.XRAY_STATS_API_PORT
    SERVER_PORT = core.SERVER_PORT
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_warn   = core._box_warn
    _box_ok     = core._box_ok
    _box_sep    = core._box_sep
    warn        = core.warn
    _users_get_outbound_breakdown = core._users_get_outbound_breakdown
    _users_get_traffic            = core._users_get_traffic
    _users_get_traffic_extended   = core._users_get_traffic_extended
    _users_get_connections_by_email = core._users_get_connections_by_email
    _fmt_bytes_ru = core._fmt_bytes_ru
    _bar_mini     = core._bar_mini
    _device_icon  = core._device_icon
    BOLD   = core.BOLD
    GREEN  = core.GREEN
    CYAN   = core.CYAN
    YELLOW = core.YELLOW
    RED    = core.RED
    DIM    = core.DIM
    WHITE  = core.WHITE
    BLUE   = core.BLUE
    NC     = core.NC

    os.system("clear")

    # Перечитываем install_mode из state.json — аргумент может быть устаревшим
    try:
        if STATE_FILE.exists():
            install_mode = json.loads(STATE_FILE.read_text()).get("install_mode", install_mode)
    except Exception:
        pass

    _box_top(f"Статистика пользователей")
    _box_row()

    # Проверяем доступность Stats API
    api_ok = False
    try:
        r = subprocess.run(
            ["bash", "-c",
             f"timeout 2 bash -c 'echo >/dev/tcp/127.0.0.1/{XRAY_STATS_API_PORT}' "
             f"2>/dev/null && echo ok || echo fail"],
            capture_output=True, text=True, timeout=6
        )
        api_ok = r.stdout.strip() == "ok"
    except Exception:
        pass

    if not api_ok:
        _box_warn("Stats API недоступен (порт не отвечает).")
        _box_warn(f"Убедитесь что Xray запущен и stats API включён на порту {XRAY_STATS_API_PORT}.")
        _box_row()
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    users = _unified_load_users()
    if not users:
        warn("Пользователей не найдено.")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # Получаем outbound-разбивку (один общий запрос)
    outbound_stats = _users_get_outbound_breakdown()
    service_tags   = {"xray-stats-api", "BLOCK", "block"}
    proxy_tags     = {t for t in outbound_stats if t not in service_tags and "direct" not in t}
    direct_tags    = {t for t in outbound_stats if "direct" in t}
    total_proxy    = sum(outbound_stats.get(t, 0) for t in proxy_tags)
    total_direct   = sum(outbound_stats.get(t, 0) for t in direct_tags)
    grand_total    = sum(v for t, v in outbound_stats.items() if t not in service_tags)

    # ── Общая сводка ──────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}Общая статистика сервера:{NC}")
    _box_row(f"  {'─'*60}")
    _box_row(f"  Суммарный трафик:    {CYAN}{_fmt_bytes_ru(grand_total)}{NC}")
    if grand_total > 0:
        proxy_pct  = total_proxy  / grand_total * 100
        direct_pct = total_direct / grand_total * 100
        bar_proxy  = _bar_mini(total_proxy,  grand_total)
        bar_direct = _bar_mini(total_direct, grand_total)
        _box_row(f"  Через прокси:        {GREEN}{_fmt_bytes_ru(total_proxy):>10}{NC}  {proxy_pct:5.1f}%  {GREEN}{bar_proxy}{NC}")
        _box_row(f"  Напрямую (direct):   {YELLOW}{_fmt_bytes_ru(total_direct):>10}{NC}  {direct_pct:5.1f}%  {YELLOW}{bar_direct}{NC}")
    else:
        _box_row(f"  {DIM}Трафика ещё не было (все счётчики = 0){NC}")

    # ── По каждому пользователю ───────────────────────────────────────────────
    _box_row(f"  {BOLD}По пользователям:{NC}")
    _box_row(f"  {'─'*60}")

    # ── Парсим access.log — работает в ОБОИХ режимах (A и B) ──────────────
    # access.log пишется на entry node всегда, независимо от режима.
    # Формат: 2024/04/22 18:45:01 accepted tcp:CLIENT_IP:PORT -> dst email:user@x
    last_seen: dict = {}
    last_ip:   dict = {}
    conn_count_by_email: dict = {}
    try:
        log_path = Path("/var/log/xray/access.log")
        if log_path.exists():
            lines_log = log_path.read_text(errors="replace").splitlines()[-15000:]
            pat_line = re.compile(
                r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})'
                r'.*?(?:tcp|udp):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+'
                r'.*?email:(\S+)'
            )
            for line_log in lines_log:
                m = pat_line.search(line_log)
                if not m:
                    continue
                date_s, time_s, client_ip, em = m.group(1), m.group(2), m.group(3), m.group(4)
                try:
                    dt_val = datetime.strptime(f"{date_s} {time_s}", "%Y/%m/%d %H:%M:%S")
                    if em not in last_seen or dt_val > last_seen[em]:
                        last_seen[em] = dt_val
                        last_ip[em]   = client_ip
                    conn_count_by_email[em] = conn_count_by_email.get(em, 0) + 1
                except Exception:
                    pass
    except Exception:
        pass

    if install_mode == "B":
        # Режим B: user>>> трафик на entry node = 0 (архитектурное ограничение).
        # Показываем: метку, IP из access.log, время, кол-во соединений.
        # Трафик показываем суммарный через exit-ноды (не per-user).
        chain_total_up   = 0
        chain_total_down = 0
        try:
            xray_bin_st = shutil.which("xray") or str(XRAY_BIN)
            r_chain = subprocess.run(
                [xray_bin_st, "api", "statsquery",
                 f"--server=127.0.0.1:{XRAY_STATS_API_PORT}",
                 "--pattern=outbound>>>chain-exit", "--reset=false"],
                capture_output=True, text=True, timeout=5
            )
            if r_chain.returncode == 0 and r_chain.stdout.strip():
                chain_data = json.loads(r_chain.stdout.strip())
                pat_chain = re.compile(r'outbound>>>chain-exit[^>]*>>>traffic>>>(uplink|downlink)')
                for entry in (chain_data.get("stat") or []):
                    val = int(entry.get("value") or 0)
                    m = pat_chain.search(entry.get("name", ""))
                    if m:
                        if m.group(1) == "uplink":
                            chain_total_up += val
                        else:
                            chain_total_down += val
        except Exception:
            pass

        # ── Общий трафик каскада ─────────────────────────────────────────
        if chain_total_up + chain_total_down > 0:
            _box_row(f"  {BOLD}Суммарный трафик через exit-ноды:{NC}")
            _box_row(f"    ↑ {GREEN}{_fmt_bytes_ru(chain_total_up):<12}{NC}  "
                  f"↓ {CYAN}{_fmt_bytes_ru(chain_total_down):<12}{NC}")

        # ── Таблица пользователей (режим B) ──────────────────────────────
        H_NUM   = 2
        H_LABEL = 24
        H_CONNS = 7
        H_IP    = 17
        H_TIME  = 14

        ansi_re_b = re.compile(r'\x1b\[[0-9;]*m')
        def _pad_b(text: str, width: int) -> str:
            visible = len(ansi_re_b.sub('', text))
            emoji_extra = sum(1 for ch in ansi_re_b.sub('', text)
                if ord(ch) > 0xFFFF or (0x1F300 <= ord(ch) <= 0x1FBFF))
            return text + ' ' * max(0, width - visible - emoji_extra)

        no_label_b = [u for u in users if not u.get("device_label")]
        if no_label_b:
            _box_row(f"  {DIM}(у {len(no_label_b)} польз. нет метки — назначьте через U→6){NC}")

        H_HDR1 = f"  {BOLD}"
        H_HDR2 = f'{"#":<{H_NUM}}  {"Метка устройства":<{H_LABEL}}  '
        H_HDR3 = f'{"Соед.":>{H_CONNS}}  {"IP подключения":<{H_IP}}  {"Последнее":<{H_TIME}}'
        print(H_HDR1 + H_HDR2 + H_HDR3 + NC)
        sep_b = ("  " + "─"*H_NUM + "  " + "─"*H_LABEL + "  " +
                 "─"*H_CONNS + "  " + "─"*H_IP + "  " + "─"*H_TIME)
        print(sep_b)

        for i, u in enumerate(users, 1):
            email        = u.get("email", u["uuid"][:8])
            device_label = u.get("device_label", "")
            icon         = _device_icon(device_label)
            if device_label:
                label_raw = f"{icon} {device_label}"
            else:
                label_raw = f"{DIM}[{u.get('name', email.split('@')[0])}]  →  U→6{NC}"

            ls    = last_seen.get(email)
            lip   = last_ip.get(email, "")
            conns = conn_count_by_email.get(email, 0)
            ts_str = ls.strftime("%d.%m %H:%M") if ls else "—"

            if lip:
                parts = lip.split(".")
                lip_disp = f"{parts[0]}.{parts[1]}.xx.xx" if len(parts) == 4 else lip
            else:
                lip_disp = "—"

            conns_col = GREEN if conns > 0 else DIM
            _box_row(f"  {i:<{H_NUM}}  {_pad_b(label_raw, H_LABEL)}  "
                  f"{conns_col}{conns:>{H_CONNS}}{NC}  "
                  f"{DIM}{lip_disp:<{H_IP}}{NC}  "
                  f"{DIM}{ts_str:<{H_TIME}}{NC}")
        _box_row(f"  {DIM}Режим B: трафик per-user недоступен на entry node (ограничение Xray){NC}")
    else:
        # Режим A — user>>> счётчики работают нормально
        # last_seen и last_ip уже заполнены выше из access.log

        # ── Вычисляем ширины колонок с учётом реального контента ───────────
        # label_disp может содержать emoji (2 символа терминала) + текст.
        # Чтобы выравнивание не ломалось, считаем печатную ширину отдельно
        # и добиваем пробелами вручную — не полагаемся на f-string :<N.
        H_NUM   = 2   # №
        H_LABEL = 24  # Метка устройства (включая 2 символа emoji + пробел)
        H_UP    = 11  # ↑ Отправлено
        H_DOWN  = 11  # ↓ Получено
        H_IP    = 17  # IP подключения
        H_TIME  = 14  # Время

        def _pad(text: str, width: int) -> str:
            """Добивает строку пробелами до width, игнорируя ANSI escape."""
            ansi_re = re.compile(r'\x1b\[[0-9;]*m')
            visible = len(ansi_re.sub('', text))
            # emoji занимают 2 позиции в терминале, учитываем
            emoji_extra = sum(
                1 for ch in ansi_re.sub('', text)
                if ord(ch) > 0xFFFF or (0x1F300 <= ord(ch) <= 0x1FBFF)
            )
            visible_width = visible + emoji_extra
            pad = max(0, width - visible_width)
            return text + ' ' * pad

        # ── Заголовок ───────────────────────────────────────────────────────
        sep = f"  {'─'*H_NUM}  {'─'*H_LABEL}  {'─'*H_UP}  {'─'*H_DOWN}  {'─'*H_IP}  {'─'*H_TIME}"
        _box_row(f"  {BOLD}"
              f"#{'':<{H_NUM-1}}  "
              f"{'Метка устройства':<{H_LABEL}}  "
              f"{'↑ Отправлено':>{H_UP}}  "
              f"{'↓ Получено':>{H_DOWN}}  "
              f"{'IP подключения':<{H_IP}}  "
              f"{'Время':<{H_TIME}}"
              f"{NC}")
        print(sep)

        # ── Предупреждение для пользователей без метки ──────────────────────
        no_label_users = [u for u in users if not u.get("device_label")]
        if no_label_users:
            _box_row(f"  {DIM}(у {len(no_label_users)} польз. нет метки — назначьте через U→6){NC}")

        for i, u in enumerate(users, 1):
            email        = u.get("email", u["uuid"][:8])
            device_label = u.get("device_label", "")
            icon         = _device_icon(device_label)

            # label_disp: если метки нет — показываем имя серым, в скобках
            if device_label:
                label_raw = f"{icon} {device_label}"
            else:
                label_raw = f"{DIM}[{u.get('name', email.split('@')[0])}]{NC}"

            up, down, _, _ = _users_get_traffic_extended(email)

            # Последнее подключение
            ls     = last_seen.get(email)
            lip    = last_ip.get(email, "")
            ts_str = ls.strftime("%d.%m %H:%M") if ls else "—"

            # Маскируем IP: показываем первые два октета + xx.xx
            if lip:
                parts = lip.split(".")
                if len(parts) == 4:
                    lip_disp = f"{parts[0]}.{parts[1]}.xx.xx"
                else:
                    lip_disp = lip
            else:
                lip_disp = "—"

            # Цвет трафика
            total_user = up + down
            if total_user == 0:
                up_col = down_col = DIM
            elif total_user > 100 * 1024**3:
                up_col = down_col = RED
            elif total_user > 50 * 1024**3:
                up_col = down_col = YELLOW
            else:
                up_col = GREEN
                down_col = CYAN

            # Собираем строку через _pad для корректного выравнивания
            num_s    = f"{i}"
            label_s  = _pad(label_raw, H_LABEL)
            up_s     = f"{up_col}{_fmt_bytes_ru(up):>{H_UP}}{NC}"
            down_s   = f"{down_col}{_fmt_bytes_ru(down):>{H_DOWN}}{NC}"
            ip_s     = f"{DIM}{lip_disp:<{H_IP}}{NC}"
            time_s   = f"{DIM}{ts_str:<{H_TIME}}{NC}"

            _box_row(f"  {num_s:<{H_NUM}}  {label_s}  {up_s}  {down_s}  {ip_s}  {time_s}")

    # ── Разбивка по outbound-тегам ────────────────────────────────────────────
    if outbound_stats:
        _box_row(f"  {BOLD}Трафик по направлениям (outbound):{NC}")
        _box_row(f"  {'─'*60}")
        _box_row(f"  {'Тег':<28} {'Объём':>12}  {'Доля':>6}  Визуализация")
        _box_row(f"  {'─'*28} {'─'*12}  {'─'*6}  {'─'*20}")
        sorted_tags = sorted(
            [(t, v) for t, v in outbound_stats.items() if t not in service_tags],
            key=lambda x: -x[1]
        )
        for tag, val in sorted_tags:
            pct = val / grand_total * 100 if grand_total else 0
            color = YELLOW if "direct" in tag else (RED if "BLOCK" in tag else GREEN)
            bar   = _bar_mini(val, grand_total)
            _box_row(f"  {tag:<28} {_fmt_bytes_ru(val):>12}  {pct:5.1f}%  {color}{bar}{NC}")

    # ── Распределение по нодам (только режим B) ────────────────────────────────
    if install_mode == "B":
        node_tags = {t: v for t, v in outbound_stats.items()
                     if ("chain-exit" in t or "balancer" in t)
                     and t not in service_tags}
        if node_tags:
            _box_row(f"  {BOLD}Распределение по exit-нодам (Режим B):{NC}")
            _box_row(f"  {'─'*60}")
            node_total = sum(node_tags.values())
            for tag, val in sorted(node_tags.items(), key=lambda x: -x[1]):
                pct = val / node_total * 100 if node_total else 0
                bar = _bar_mini(val, node_total)
                _box_row(f"  {tag:<28} {CYAN}{_fmt_bytes_ru(val):>12}{NC}  {pct:5.1f}%  {CYAN}{bar}{NC}")

    # ── Активные соединения ────────────────────────────────────────────────────
    try:
        r_ss = subprocess.run(
            ["ss", "-tn", "state", "established"],
            capture_output=True, text=True, timeout=5
        )
        conn_lines = [l for l in r_ss.stdout.splitlines()
                      if f":{SERVER_PORT}" in l or ":443" in l]
        conn_count = len(conn_lines)
        if conn_count > 0:
            _box_row(f"  {BOLD}Активных соединений:{NC} {GREEN}{conn_count}{NC}")
    except Exception:
        pass

    _box_bottom()
    input(f"{BLUE}Нажмите Enter для возврата...{NC}")


# =============================================================================
#  Region C — v2: СТАТИСТИКА С СОРТИРОВКОЙ + CSV-ЭКСПОРТ
# =============================================================================
def _do_user_stats_screen_v2(sort_key: str = "traffic") -> None:
    """
    Расширенный экран статистики с сортировкой.
    Дублирует логику _do_user_stats_screen, добавляя сортировку и экспорт CSV.
    """
    core = _core_module()
    STATE_FILE  = core.STATE_FILE
    XRAY_BIN    = core.XRAY_BIN
    XRAY_STATS_API_PORT = core.XRAY_STATS_API_PORT
    _STATS_SORT_KEYS = core._STATS_SORT_KEYS
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_warn   = core._box_warn
    _box_ok     = core._box_ok
    warn        = core.warn
    _users_get_traffic_extended = core._users_get_traffic_extended
    _fmt_bytes_ru = core._fmt_bytes_ru
    _device_icon  = core._device_icon
    _do_user_stats_sorted = core._do_user_stats_sorted
    _export_stats_csv     = core._export_stats_csv
    BOLD   = core.BOLD
    GREEN  = core.GREEN
    CYAN   = core.CYAN
    YELLOW = core.YELLOW
    RED    = core.RED
    DIM    = core.DIM
    BLUE   = core.BLUE
    NC     = core.NC

    os.system("clear")
    try:
        if STATE_FILE.exists():
            install_mode = json.loads(STATE_FILE.read_text()).get("install_mode", "A")
        else:
            install_mode = "A"
    except Exception:
        install_mode = "A"

    print()
    _box_top(f"Статистика пользователей")
    label_key = next((v[1] for k, v in _STATS_SORT_KEYS.items()
                      if v[0] == sort_key), "")
    if label_key:
        _box_row(f"  Сортировка: {label_key}")
        _box_bottom()

    # Проверка Stats API
    api_ok = False
    try:
        r = subprocess.run(
            ["bash", "-c",
             f"timeout 2 bash -c 'echo >/dev/tcp/127.0.0.1/{XRAY_STATS_API_PORT}' "
             f"2>/dev/null && echo ok || echo fail"],
            capture_output=True, text=True, timeout=6
        )
        api_ok = r.stdout.strip() == "ok"
    except Exception:
        pass

    users = _unified_load_users()
    if not users:
        warn("Пользователей не найдено.")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # Парсим access.log
    last_seen: dict = {}
    last_ip:   dict = {}
    try:
        log_path = Path("/var/log/xray/access.log")
        if log_path.exists():
            pat_line = re.compile(
                r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})'
                r'.*?(?:tcp|udp):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+'
                r'.*?email:(\S+)'
            )
            for line in log_path.read_text(errors="replace").splitlines()[-10000:]:
                m = pat_line.search(line)
                if not m:
                    continue
                try:
                    dt_val = datetime.strptime(
                        f"{m.group(1)} {m.group(2)}", "%Y/%m/%d %H:%M:%S")
                    em = m.group(4)
                    if em not in last_seen or dt_val > last_seen[em]:
                        last_seen[em] = dt_val
                        last_ip[em]   = m.group(3)
                except Exception:
                    pass
    except Exception:
        pass

    # ── Режим B: user>>> счётчики = 0 на entry node (архитектурное ограничение Xray) ──
    # В каскаде весь трафик уходит через chain-exit outbound — user-счётчики не
    # инкрементируются на entry-ноде. Показываем суммарный трафик exit-нод +
    # данные из access.log (IP, время, число соединений).
    if install_mode == "B":
        # Суммарный трафик через exit-ноды
        chain_up = chain_down = 0
        if api_ok:
            try:
                xray_bin_st = shutil.which("xray") or str(XRAY_BIN)
                r_chain = subprocess.run(
                    [xray_bin_st, "api", "statsquery",
                     f"--server=127.0.0.1:{XRAY_STATS_API_PORT}",
                     "--pattern=outbound>>>chain-exit", "--reset=false"],
                    capture_output=True, text=True, timeout=5
                )
                if r_chain.returncode == 0 and r_chain.stdout.strip():
                    chain_data = json.loads(r_chain.stdout.strip())
                    pat_chain = re.compile(r'outbound>>>chain-exit[^>]*>>>traffic>>>(uplink|downlink)')
                    for entry in (chain_data.get("stat") or []):
                        val = int(entry.get("value") or 0)
                        m = pat_chain.search(entry.get("name", ""))
                        if m:
                            if m.group(1) == "uplink":
                                chain_up += val
                            else:
                                chain_down += val
            except Exception:
                pass

        if chain_up + chain_down > 0:
            print(f"  {BOLD}Суммарный трафик через exit-ноды:{NC}")
            print(f"    ↑ {GREEN}{_fmt_bytes_ru(chain_up):<12}{NC}  "                  f"↓ {CYAN}{_fmt_bytes_ru(chain_down):<12}{NC}")
            print()

        # Таблица: метка, соединения, IP, время (трафик per-user недоступен)
        conn_count: dict = {}
        for line in (Path("/var/log/xray/access.log").read_text(errors="replace").splitlines()[-15000:]
                     if Path("/var/log/xray/access.log").exists() else []):
            m2 = re.search(r'email:(\S+)', line)
            if m2:
                conn_count[m2.group(1)] = conn_count.get(m2.group(1), 0) + 1

        ansi_re_b = re.compile(r'\x1b\[[0-9;]*m')
        def _pad_b(text: str, width: int) -> str:
            visible = len(ansi_re_b.sub('', text))
            emoji_extra = sum(1 for ch in ansi_re_b.sub('', text)
                if ord(ch) > 0xFFFF or (0x1F300 <= ord(ch) <= 0x1FBFF))
            return text + ' ' * max(0, width - visible - emoji_extra)

        H_NUM_B = 2; H_LABEL_B = 24; H_CONNS_B = 7; H_IP_B = 17; H_TIME_B = 14
        no_label_b = [u for u in users if not u.get("device_label")]
        if no_label_b:
            print(f"  {DIM}(у {len(no_label_b)} польз. нет метки — назначьте через U→6){NC}")
            print()
        print(f"  {BOLD}{'#':<{H_NUM_B}}  {'Метка устройства':<{H_LABEL_B}}  "              f"{'Соед.':>{H_CONNS_B}}  {'IP подключения':<{H_IP_B}}  {'Последнее':<{H_TIME_B}}{NC}")
        print(f"  {'─'*H_NUM_B}  {'─'*H_LABEL_B}  {'─'*H_CONNS_B}  {'─'*H_IP_B}  {'─'*H_TIME_B}")

        # Сортировка в режиме B
        users_b = list(users)
        if sort_key == "last":
            users_b.sort(key=lambda u: last_seen.get(u.get("email","")) or datetime.min, reverse=True)
        elif sort_key == "name":
            users_b.sort(key=lambda u: u.get("name", "").lower())
        elif sort_key == "label":
            users_b.sort(key=lambda u: u.get("device_label", "").lower())
        else:  # traffic / default — по числу соединений
            users_b.sort(key=lambda u: -conn_count.get(u.get("email",""), 0))

        for i, u in enumerate(users_b, 1):
            email   = u.get("email", u["uuid"][:8])
            label   = u.get("device_label", "")
            icon    = _device_icon(label)
            lraw    = (f"{icon} {label}" if label
                       else f"{DIM}[{u.get('name', email.split('@')[0])}]  →  U→6{NC}")
            ls      = last_seen.get(email)
            lip     = last_ip.get(email, "")
            conns   = conn_count.get(email, 0)
            ts_str  = ls.strftime("%d.%m %H:%M") if ls else "—"
            lip_disp = (f"{'.'.join(lip.split('.')[:2])}.xx.xx"
                        if lip and len(lip.split('.')) == 4 else lip or "—")
            cc = GREEN if conns > 0 else DIM
            print(f"  {i:<{H_NUM_B}}  {_pad_b(lraw, H_LABEL_B)}  "                  f"{cc}{conns:>{H_CONNS_B}}{NC}  "                  f"{DIM}{lip_disp:<{H_IP_B}}{NC}  "                  f"{DIM}{ts_str:<{H_TIME_B}}{NC}")
        print()
        print(f"  {DIM}Режим B: трафик per-user недоступен на entry node (ограничение Xray).{NC}")
        print(f"  {DIM}Общий трафик показан через outbound>>>chain-exit.{NC}")
        print()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── Режим A: user>>> счётчики работают нормально ──────────────────────────
    # Собираем данные по каждому пользователю
    rows = []
    for u in users:
        email = u.get("email", u["uuid"][:8])
        if api_ok:
            up, down, _, _ = _users_get_traffic_extended(email)
        else:
            up = down = 0
        ls  = last_seen.get(email)
        lip = last_ip.get(email, "")
        rows.append({
            "user":  u,
            "email": email,
            "up":    up,
            "down":  down,
            "total": up + down,
            "last":  ls,
            "ip":    lip,
        })

    # Сортировка
    if sort_key == "traffic":
        rows.sort(key=lambda x: -(x["total"]))
    elif sort_key == "last":
        rows.sort(key=lambda x: x["last"] or datetime.min, reverse=True)
    elif sort_key == "name":
        rows.sort(key=lambda x: x["user"].get("name", "").lower())
    elif sort_key == "label":
        rows.sort(key=lambda x: x["user"].get("device_label", "").lower())

    if not api_ok:
        warn("Stats API недоступен — трафик показан как 0")
        print()

    # Выравнивание
    ansi_re = re.compile(r'\x1b\[[0-9;]*m')
    def _pad(text: str, width: int) -> str:
        visible = len(ansi_re.sub('', text))
        emoji_extra = sum(
            1 for ch in ansi_re.sub('', text)
            if ord(ch) > 0xFFFF or (0x1F300 <= ord(ch) <= 0x1FBFF)
        )
        return text + ' ' * max(0, width - visible - emoji_extra)

    H_NUM   = 2
    H_LABEL = 24
    H_UP    = 11
    H_DOWN  = 11
    H_IP    = 17
    H_TIME  = 14

    sep = f"  {'─'*H_NUM}  {'─'*H_LABEL}  {'─'*H_UP}  {'─'*H_DOWN}  {'─'*H_IP}  {'─'*H_TIME}"
    print(f"  {BOLD}{'#':<{H_NUM}}  "
          f"{'Метка устройства':<{H_LABEL}}  "
          f"{'↑ Отправлено':>{H_UP}}  "
          f"{'↓ Получено':>{H_DOWN}}  "
          f"{'IP подключения':<{H_IP}}  "
          f"{'Время':<{H_TIME}}{NC}")
    print(sep)

    no_label = [r for r in rows if not r["user"].get("device_label")]
    if no_label:
        print(f"  {DIM}({len(no_label)} польз. без метки — назначьте через U→6){NC}")
        print()

    for i, row in enumerate(rows, 1):
        u      = row["user"]
        label  = u.get("device_label", "")
        icon   = _device_icon(label)
        label_raw = f"{icon} {label}" if label else f"{DIM}[{u.get('name', row['email'].split('@')[0])}]{NC}"

        up_b   = row["up"]
        down_b = row["down"]
        ls     = row["last"]
        lip    = row["ip"]

        if lip:
            parts = lip.split(".")
            lip_disp = f"{parts[0]}.{parts[1]}.xx.xx" if len(parts) == 4 else lip
        else:
            lip_disp = "—"

        ts_str = ls.strftime("%d.%m %H:%M") if ls else "—"
        total  = up_b + down_b

        if not api_ok or total == 0:
            up_col = down_col = DIM
        elif total > 100 * 1024**3:
            up_col = down_col = RED
        elif total > 50 * 1024**3:
            up_col = down_col = YELLOW
        else:
            up_col   = GREEN
            down_col = CYAN

        # Флаг отключённого пользователя
        disabled_mark = f" {RED}[откл]{NC}" if u.get("disabled") else ""

        print(f"  {i:<{H_NUM}}  {_pad(label_raw, H_LABEL)}  "
              f"{up_col}{_fmt_bytes_ru(up_b):>{H_UP}}{NC}  "
              f"{down_col}{_fmt_bytes_ru(down_b):>{H_DOWN}}{NC}  "
              f"{DIM}{lip_disp:<{H_IP}}{NC}  "
              f"{DIM}{ts_str:<{H_TIME}}{NC}"
              f"{disabled_mark}")

    print()
    print(f"  {DIM}[S] Сменить сортировку  [C] Экспорт CSV  [Enter] Выход{NC}")
    ch = input(f"  ").strip().lower()
    if ch == "s":
        _do_user_stats_sorted()
        return
    elif ch == "c":
        _export_stats_csv(rows)
        input(f"{BLUE}Нажмите Enter...{NC}")
