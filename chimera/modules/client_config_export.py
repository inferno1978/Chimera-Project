"""
chimera/modules/client_config_export.py
───────────────────────────────────────────────────────────────────────────────
Генерация и экспорт клиентских конфигов + одноразовый share-сервер.

Три функции (объединены, т.к. все работают с клиентскими конфигами):

1. **do_generate_client_config** — генерирует Clash Meta YAML и Sing-box JSON
   из state.json и сохраняет их в /root/xray-client-configs/.

2. **do_export_client_config** — экспорт клиентских конфигов (Clash Meta YAML,
   Sing-box JSON, VLESS-ссылка) в файлы на сервере + опциональная передача
   по SFTP на другой сервер. Переиспользует do_generate_client_config.

3. **do_share_config_server** — поднимает одноразовый HTTP-сервер на случайном
   порту с токеном (5 минут или 1 просмотр). Пользователь заходит с телефона,
   получает QR и VLESS-ссылки, сервер завершается.

Точки входа из _core.py:
    from chimera.modules.client_config_export import (
        do_generate_client_config, do_export_client_config, do_share_config_server,
    )

Доступ к helpers ядра (_box_*, _run, log_to_file, command_exists, STATE_FILE,
_users_load, _unified_show_links, get_server_ip, warn/info/success, цвета) —
через importlib (lazy binding), как и в других извлечённых модулях
(warp.py, smart_balancer.py, failover.py, standalone_screens.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import http.server
import json
import os
import random
import re
import string
import tempfile
import textwrap
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules (был импортирован
    одним из поздних lazy-вызовов внутри других модулей) — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  ГЕНЕРАЦИЯ CLASH META / SING-BOX КОНФИГА
# =============================================================================
def do_generate_client_config() -> None:
    """Генерирует готовый YAML для Clash Meta и JSON для Sing-box из state.json."""
    core = _core_module()
    _box_top     = core._box_top
    _box_row     = core._box_row
    _box_bottom  = core._box_bottom
    _box_warn    = core._box_warn
    _box_ok      = core._box_ok
    log_to_file  = core.log_to_file
    STATE_FILE   = core.STATE_FILE
    CYAN, NC, DIM = core.CYAN, core.NC, core.DIM

    print()
    print()
    _box_top(f"Генерация клиентских конфигов")

    if not STATE_FILE.exists():
        _box_warn("state.json не найден — сначала выполните установку")
        return

    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _box_warn(f"Не удалось прочитать state.json: {e}")
        return

    domain    = state.get("domain", "")
    port      = state.get("server_port", 443)
    vuuid     = state.get("uuid", "")
    # pbk/sid — с fallback на живой config.json (частично битый
    # state.json больше не выдаёт Clash/vless-конфиги с пустыми ключами).
    try:
        import importlib as _il
        _core_mod = _il.import_module("chimera._core")
        pub_key, short_id, _spx_live = _core_mod._reality_transport_params_from_state(state)
    except Exception:
        pub_key   = state.get("public_key", "")
        short_id  = state.get("short_id", "")
    proto     = state.get("protocol_mode", "reality")
    fp        = state.get("fingerprint", "chrome")
    # === FIX 2: SNI строго из reality_dest (AWG/REALITY) или domain (классика/xHTTP) ===
    # Ключ "sni" не сохраняется в state.json — state.get("sni", domain) всегда давал domain.
    # Важно: reality_dest и awg_exit_enabled сохраняются ТОЛЬКО при INSTALL_MODE="B" (AWG/chain).
    # При Mode A эти ключи отсутствуют → дефолты False/"" → sni = domain. Это верно.
    _install_mode = state.get("install_mode", "A")
    _awg_exit = state.get("awg_exit_enabled", False) and _install_mode == "B"
    _reality_dest = state.get("reality_dest", "")
    if proto == "reality" and _awg_exit and _reality_dest:
        sni = _reality_dest   # Mode B + AWG: SNI = домен маскировки (чужой сайт)
    elif proto == "reality":
        sni = domain          # Mode A классика или Mode B chain: SNI = собственный домен
    else:
        sni = domain          # xHTTP TLS: SNI = собственный домен
    # === END FIX 2 ===
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "stream-up")
    xtls_flow_val = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    if not domain or not vuuid:
        _box_warn("Домен или UUID не найдены в state.json")
        return

    # --- Clash Meta YAML ---
    if proto == "reality":
        # REALITY + mihomo (рецепт B, Xray-core 26.9.8+): серверная
        # библиотека xtls/reality требует keyShare X25519MLKEM768 в
        # ClientHello; в mihomo он есть только у HelloChrome_Auto, опция
        # support-x25519mlkem768 (внутри reality-opts) запрещает его
        # вырезание. FP фиксирован на chrome (живой тест 2026-09-10:
        # chrome+флаг работает и против новых, и против старых ядер).
        # Ссылка vless-link.txt ниже по-прежнему берёт fp из state.json —
        # Xray-семья клиентов выбирает FP сама по версии ядра.
        clash_proxy = textwrap.dedent(f"""\
            proxies:
              - name: VLESS-Reality
                type: vless
                server: {domain}
                port: {port}
                uuid: {vuuid}
                network: tcp
                tls: true
                udp: true
                flow: {xtls_flow_val}
                reality-opts:
                  public-key: {pub_key}
                  short-id: {short_id}
                  support-x25519mlkem768: true
                client-fingerprint: chrome
                servername: {sni}

            proxy-groups:
              - name: Proxy
                type: select
                proxies:
                  - VLESS-Reality

            rules:
              - MATCH,Proxy
        """)
    else:  # xhttp
        clash_proxy = textwrap.dedent(f"""\
            proxies:
              - name: VLESS-xHTTP
                type: vless
                server: {domain}
                port: {port}
                uuid: {vuuid}
                network: http
                tls: true
                udp: false
                http-opts:
                  path: [{xhttp_path}]
                client-fingerprint: {fp}
                servername: {domain}

            proxy-groups:
              - name: Proxy
                type: select
                proxies:
                  - VLESS-xHTTP

            rules:
              - MATCH,Proxy
        """)

    # --- Sing-box JSON ---
    # CDN masking: при активном профиле добавляем экспертные extra-поля
    # в transport и host в URL. Симметрично серверному inbound.
    _cdn_masking_active = bool(state.get("xhttp_cdn_masking", False))
    if _cdn_masking_active:
        try:
            from chimera.modules.xhttp_cdn_masking import (
                build_xhttp_cdn_masking_client_xhttp_settings,
                CDN_MASKING_HOST,
            )
            _client_xhttp = build_xhttp_cdn_masking_client_xhttp_settings(domain, xhttp_path)
            _cdn_host_param = CDN_MASKING_HOST or domain
        except ImportError:
            _cdn_masking_active = False  # fallback на обычный xhttp
            _cdn_host_param = domain
    if proto == "reality":
        singbox = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": vuuid,
                **( {"flow": xtls_flow_val} if xtls_flow_val else {} ),
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": fp},
                    "reality": {
                        "enabled": True,
                        "public_key": pub_key,
                        "short_id": short_id,
                    }
                }
            }]
        }
    elif _cdn_masking_active:
        # CDN masking: sing-box outbound с расширенным transport (extra + host).
        # Структура: transport.type=xhttp + mode + path + host + extra (симметрично серверу).
        # ВАЖНО: mode берём из _client_xhttp (всегда "auto" = _CDN_MASKING_XHTTP_MODE),
        # не из state["xhttp_mode"] — чтобы гарантировать синхрон с сервером.
        singbox = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": vuuid,
                "transport": {
                    "type": "xhttp",
                    "mode": _client_xhttp.get("mode", "auto"),
                    "path": xhttp_path,
                    "host": _cdn_host_param,
                    "extra": _client_xhttp.get("extra", {}),
                },
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": fp},
                }
            }]
        }
    else:
        singbox = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": vuuid,
                "transport": {
                    "type": "xhttp",
                    "mode": xhttp_mode,
                    "path": xhttp_path,
                },
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": fp},
                }
            }]
        }

    # Сохраняем файлы
    out_dir = Path("/root/xray-client-configs")
    out_dir.mkdir(exist_ok=True)
    clash_file   = out_dir / "clash-meta.yaml"
    singbox_file = out_dir / "sing-box.json"
    hiddify_file = out_dir / "hiddify.json"
    vless_link_file = out_dir / "vless-link.txt"

    clash_file.write_text(clash_proxy)

    # --- Hiddify JSON --- (тот же формат что sing-box, с routing)
    # ВАЖНО: Hiddify-копия создаётся ДО инъекции singbox_client_rulesets.
    # Hiddify использует схему routing → rules (отличается от sing-box
    # route → rule_set/rules). Если бы инъекция попала в Hiddify-конфиг,
    # mixing схем вызвал бы путаницу. Поэтому: shallow-copy делаем сейчас,
    # инъекцию в singbox — ниже, после записи hiddify.json.
    hiddify_config = {**singbox}
    hiddify_config["routing"] = {
        "rules": [{"type": "default", "outbound": "vless-out"}]
    }
    hiddify_file.write_text(json.dumps(hiddify_config, indent=2, ensure_ascii=False))

    # --- Sing-box JSON ---
    # singbox_client_rulesets: опциональная инъекция route.rule_set + rules
    # с готовыми .srs-списками для Podkop/OpenWrt (РФ-домены → direct и т.д.).
    # По умолчанию ВЫКЛЮЧЕНО — обратная совместимость 100%.
    # См. chimera/modules/singbox_client_rulesets.py
    try:
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        inject_route_rulesets(singbox, "vless-out")
    except Exception as _e:
        log_to_file("WARN", f"singbox_client_rulesets.inject failed: {_e}")

    singbox_file.write_text(json.dumps(singbox, indent=2, ensure_ascii=False))

    # --- VLESS-ссылка --- (plain text, для импорта в v2rayN/Karing/NekoBox)
    if proto == "reality":
        vless_link = (f"vless://{vuuid}@{domain}:{port}"
                      f"?encryption=none&flow={xtls_flow_val}"
                      f"&security=reality&sni={sni}"
                      f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                      f"&type=tcp#VLESS-Reality")
    else:
        from urllib.parse import quote as _url_quote
        xhttp_path_enc = _url_quote(xhttp_path, safe="")
        # Базовая VLESS-ссылка для xHTTP с mode= из state.json.
        # ВАЖНО: mode берётся из state["xhttp_mode"], который синхронизирован
        # с серверным config.json через _build_xhttp_settings(mode=XHTTP_MODE).
        # Для CDN masking mode="auto" (через _CDN_MASKING_XHTTP_MODE).
        vless_link = (f"vless://{vuuid}@{domain}:{port}"
                      f"?encryption=none&security=tls&sni={domain}"
                      f"&fp={fp}&type=xhttp&path={xhttp_path_enc}"
                      f"&mode={xhttp_mode}#VLESS-xHTTP")
        # CDN masking: добавляем host= параметр (перед #fragment) и суффикс
        # -CDN к label, чтобы визуально отличить ссылку в клиенте.
        # Пост-обработка строки — не трогаем исходный f-string выше.
        if _cdn_masking_active:
            _host_query = f"&host={_url_quote(_cdn_host_param, safe='')}"
            # Вставляем host= перед #VLESS-xHTTP, добавляем -CDN к label.
            vless_link = vless_link.replace(
                "#VLESS-xHTTP",
                f"{_host_query}#VLESS-xHTTP-CDN",
                1,
            )
    vless_link_file.write_text(vless_link + "\n")

    # ── iOS/Karing-совместимый вариант ссылки ─────────────────────────────
    # Для REALITY: серверный clients[] хранит "flow": "xtls-rprx-vision"
    # для этого UUID. Постпроцессор to_ios_karing_link убирает flow из
    # ссылки, но без shadow-клиента Xray рвёт хендшейк. Поэтому создаём
    # shadow (без flow) и собираем ссылку на его UUID.
    # Для xHTTP: flow не используется в принципе — обычный vless_link
    # уже iOS-safe, просто копируем.
    # Если config.json недоступен (тестовое окружение или Xray не установлен) —
    # graceful fallback: оставляем только постпроцессор. Это лучше, чем
    # ронять весь do_generate_client_config, ведь остальные 4 файла
    # (clash/singbox/hiddify/vless-link) уже сгенерированы.
    ios_link_file = out_dir / "vless-link-ios.txt"
    if proto == "reality":
        try:
            from chimera.modules.users_manager import (
                _users_get_config, _users_get_or_create_ios_shadow,
                _users_gen_link,
            )
            from chimera.modules.ios_link_variant import to_ios_karing_link
            try:
                cfg_path = _users_get_config()
            except SystemExit:
                # _users_get_config вызывает die() если config.json не найден.
                # В тестовом окружении это норма — fallback на постпроцессор.
                raise FileNotFoundError("config.json not found")
            with cfg_path.open() as _f:
                _c = json.load(_f)
            _clients = (_c.get("inbounds", [{}])[0]
                        .get("settings", {}).get("clients", []))
            _base = next((cl for cl in _clients if cl.get("id", "") == vuuid), None)
            if not _base or not _base.get("email"):
                _box_warn("iOS-link: root-юзер не найден в clients[] или нет email — "
                          "vless-link-ios.txt не создан. Примените список [5] в менеджере.")
            else:
                _shadow = _users_get_or_create_ios_shadow(cfg_path, _base["email"])
                if _shadow is None:
                    # Ненормально для reality — fallback на обычную ссылку.
                    _box_warn("iOS-link: shadow не создан (нетипично для reality) — "
                              "vless-link-ios.txt = обычная ссылка.")
                    ios_link_file.write_text(to_ios_karing_link(vless_link) + "\n")
                else:
                    _shadow_uuid, _shadow_email = _shadow
                    _ios_link = to_ios_karing_link(
                        _users_gen_link(cfg_path, _shadow_uuid, _shadow_email)
                    )
                    ios_link_file.write_text(_ios_link + "\n")
        except FileNotFoundError:
            # Config Xray не найден — fallback на постпроцессор.
            from chimera.modules.ios_link_variant import to_ios_karing_link
            ios_link_file.write_text(to_ios_karing_link(vless_link) + "\n")
        except Exception as _ios_e:
            _box_warn(f"iOS-link: не удалось создать shadow-клиент: {_ios_e}")
            # Фолбэк: хотя бы постпроцессор, лучше чем ничего.
            from chimera.modules.ios_link_variant import to_ios_karing_link
            ios_link_file.write_text(to_ios_karing_link(vless_link) + "\n")
    else:
        # xHTTP — shadow не нужен, flow нет.
        from chimera.modules.ios_link_variant import to_ios_karing_link
        ios_link_file.write_text(to_ios_karing_link(vless_link) + "\n")

    _box_ok(f"Clash Meta   → {clash_file}")
    _box_ok(f"Sing-box     → {singbox_file}")
    _box_ok(f"Hiddify      → {hiddify_file}")
    _box_ok(f"VLESS-ссылка → {vless_link_file}")
    _box_ok(f"iOS/Karing   → {ios_link_file}")
    _box_row()
    _box_row(f"  {DIM}Скопируйте файлы на клиентское устройство:{NC}")
    _box_row(f"    {CYAN}scp root@{domain}:{clash_file} .{NC}")
    _box_row(f"    {CYAN}scp root@{domain}:{singbox_file} .{NC}")
    _box_row(f"    {CYAN}scp root@{domain}:{hiddify_file} .{NC}")
    _box_row(f"    {CYAN}scp root@{domain}:{vless_link_file} .{NC}")
    _box_row(f"    {CYAN}scp root@{domain}:{ios_link_file} .{NC}")
    _box_bottom()
    log_to_file("INFO", f"Client configs generated: {clash_file}, {singbox_file}, {hiddify_file}, {vless_link_file}, {ios_link_file}")


# =============================================================================
#  ЭКСПОРТ КОНФИГА КЛИЕНТА (SFTP)
# =============================================================================
def do_export_client_config() -> None:
    """
    Экспорт клиентских конфигов (Clash Meta YAML, Sing-box JSON, VLESS-ссылка)
    в файл на сервере и опционально — передача по SFTP на локальную машину.

    Шаги:
      1. Генерирует конфиги (переиспользует логику do_generate_client_config).
      2. Показывает готовые scp-команды для скачивания.
      3. Предлагает скопировать VLESS-ссылку в файл.
      4. Опционально: push через sftp если sshpass установлен.
    """
    core = _core_module()
    _box_top     = core._box_top
    _box_row     = core._box_row
    _box_sep     = core._box_sep
    _box_bottom  = core._box_bottom
    _box_warn    = core._box_warn
    _box_ok      = core._box_ok
    info         = core.info
    warn         = core.warn
    success      = core.success
    _run         = core._run
    command_exists = core.command_exists
    STATE_FILE   = core.STATE_FILE
    CYAN, NC, DIM = core.CYAN, core.NC, core.DIM

    print()
    _box_top("📤  Экспорт конфига клиента")

    if not STATE_FILE.exists():
        _box_warn("state.json не найден — сначала выполните установку")
        _box_bottom()
        return

    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _box_warn(f"Не удалось прочитать state.json: {e}")
        _box_bottom()
        return

    domain = state.get("domain", "")
    if not domain:
        _box_warn("Домен не найден в state.json")
        _box_bottom()
        return

    # --- Шаг 1: генерируем файлы конфигов ---
    _box_row(f"  {DIM}Генерирую конфиги...{NC}")
    out_dir = Path("/root/xray-client-configs")
    out_dir.mkdir(exist_ok=True)

    # Вызываем существующую функцию генерации (она сохраняет файлы)
    try:
        do_generate_client_config()
    except Exception as e:
        _box_warn(f"Ошибка генерации конфигов: {e}")
        _box_bottom()
        return

    clash_file   = out_dir / "clash-meta.yaml"
    singbox_file = out_dir / "sing-box.json"
    link_file    = Path("/root/vless_link.txt")

    # --- Шаг 2: собираем список готовых файлов ---
    ready_files = []
    for fpath in (clash_file, singbox_file, link_file):
        if fpath.exists():
            size_kb = fpath.stat().st_size // 1024 or 1
            ready_files.append(fpath)
            _box_ok(f"{fpath}  ({size_kb} КБ)")

    if not ready_files:
        _box_warn("Не найдено ни одного файла для экспорта")
        _box_bottom()
        return

    # --- Шаг 3: scp-команды ---
    _box_sep()
    _box_row(f"  {CYAN}Скачать на свой компьютер (выполните локально):{NC}")
    for fpath in ready_files:
        _box_row(f"    {DIM}scp root@{domain}:{fpath} ./{fpath.name}{NC}")

    # --- Шаг 4: единая команда скачать всё сразу ---
    files_str = " ".join(str(f) for f in ready_files)
    _box_row()
    _box_row(f"  {CYAN}Всё сразу:{NC}")
    _box_row(f"    {DIM}scp root@{domain}:{out_dir}/* ./xray-configs/{NC}")

    # --- Шаг 5: опциональный SFTP push ---
    _box_sep()
    _box_row(f"  {DIM}Хотите передать файлы на другой сервер по SFTP? (опционально){NC}")
    _box_bottom()

    try:
        ans = input(f"  Передать по SFTP? [y/N]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        ans = ""

    if ans != "y":
        return

    # Проверяем наличие sftp
    if not command_exists("sftp"):
        warn("sftp не найден — установите openssh-client")
        return

    try:
        remote_host = input("  Хост назначения (user@host): ").strip()
        remote_path = input("  Путь на хосте [/root/xray-configs/]: ").strip() or "/root/xray-configs/"
    except (KeyboardInterrupt, EOFError):
        info("Отмена")
        return

    if not remote_host:
        warn("Хост не указан — отмена")
        return

    info(f"Передача файлов на {remote_host}:{remote_path} ...")
    # Создаём удалённую директорию и передаём файлы через sftp batch
    batch_lines = [f"mkdir {remote_path}"]
    for fpath in ready_files:
        batch_lines.append(f"put {fpath} {remote_path}{fpath.name}")
    batch_lines.append("bye")
    batch_content = "\n".join(batch_lines) + "\n"

    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sftp_batch",
                                         delete=False) as tf:
            tf.write(batch_content)
            batch_path = tf.name

        r = _run(
            ["sftp", "-b", batch_path, "-o", "StrictHostKeyChecking=accept-new",
             remote_host],
            capture=False, check=False
        )
        Path(batch_path).unlink(missing_ok=True)

        if r.returncode == 0:
            success(f"Файлы переданы на {remote_host}:{remote_path}")
        else:
            warn(f"sftp завершился с кодом {r.returncode} — проверьте подключение")
    except Exception as e:
        warn(f"Ошибка SFTP: {e}")


# =============================================================================
#  ОДНОРАЗОВЫЙ SHARE-СЕРВЕР (HTTP + QR)
# =============================================================================
def do_share_config_server() -> None:
    """
    Поднимает одноразовый HTTP-сервер на случайном порту с токеном.
    Пользователь заходит с телефона, получает QR и ссылки, сервер завершается.
    """
    core = _core_module()
    _box_top     = core._box_top
    _box_row     = core._box_row
    _box_bottom  = core._box_bottom
    _box_warn    = core._box_warn
    _box_info    = core._box_info
    info         = core.info
    warn         = core.warn
    success      = core.success
    _run         = core._run
    log_to_file  = core.log_to_file
    get_server_ip = core.get_server_ip
    STATE_FILE   = core.STATE_FILE
    _users_load  = core._users_load
    _unified_show_links = core._unified_show_links
    CYAN, NC, DIM, GREEN, BOLD = core.CYAN, core.NC, core.DIM, core.GREEN, core.BOLD

    print()
    print()
    _box_top(f"Разовая ссылка для передачи конфига")

    if not STATE_FILE.exists():
        _box_warn("state.json не найден — сначала выполните установку")
        return
    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _box_warn(f"Не удалось прочитать state.json: {e}")
        return

    # Собираем VLESS-ссылки
    links: list[dict] = []
    try:
        users = _users_load()
        if users:
            for u in users[:5]:
                lnks = _unified_show_links(u, print_output=False)
                if lnks:
                    links.append({"name": u.get("name", "user"), "links": lnks})
        if not links:
            domain   = state.get("domain", "")
            vuuid    = state.get("uuid", "")
            # pbk/sid с fallback на живой config.json
            try:
                pub_key, short_id, _spx2 = core._reality_transport_params_from_state(state)
            except Exception:
                pub_key  = state.get("public_key", "")
                short_id = state.get("short_id", "")
            fp       = state.get("fingerprint", "chrome")
            port     = state.get("server_port", 443)
            proto    = state.get("protocol_mode", "reality")
            # SNI: при Mode B + AWG — домен маскировки, иначе собственный домен.
            # Ключ "sni" не сохраняется в state.json, поэтому читаем reality_dest.
            _sc_install_mode = state.get("install_mode", "A")
            _sc_awg = state.get("awg_exit_enabled", False) and _sc_install_mode == "B"
            _sc_reality_dest = state.get("reality_dest", "")
            if proto == "reality" and _sc_awg and _sc_reality_dest:
                sni = _sc_reality_dest
            else:
                sni = domain
            if proto == "reality":
                link = (f"vless://{vuuid}@{domain}:{port}"
                        f"?encryption=none&flow=xtls-rprx-vision"
                        f"&security=reality&sni={sni}"
                        f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                        f"&type=tcp#VLESS-Reality")
            else:
                xhttp_path = urllib.parse.quote(state.get("xhttp_path", "/"), safe="")
                xhttp_mode = state.get("xhttp_mode", "stream-up")
                link = (f"vless://{vuuid}@{domain}:{port}"
                        f"?encryption=none&security=tls&sni={domain}"
                        f"&fp={fp}&type=xhttp&path={xhttp_path}"
                        f"&mode={xhttp_mode}#VLESS-xHTTP")
            links.append({"name": "default", "links": [link]})
    except Exception as e:
        _box_warn(f"Ошибка сборки ссылок: {e}")
        return

    if not links:
        _box_warn("Нет ссылок для передачи")
        return

    token      = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    share_port = random.randint(50000, 59999)
    server_ip  = get_server_ip("4") or "YOUR_SERVER_IP"

    def _make_html() -> str:
        rows = []
        for u_entry in links:
            for lnk in u_entry.get("links", []):
                encoded = urllib.parse.quote(lnk, safe="")
                qr_url  = f"https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={encoded}"
                rows.append(f"""
                <div class="card">
                  <h3>{u_entry['name']}</h3>
                  <img src="{qr_url}" alt="QR" style="border-radius:8px;border:1px solid #ddd"/>
                  <p style="word-break:break-all;font-size:10px;color:#666;margin:8px 0">{lnk}</p>
                  <a href="{lnk}" style="display:inline-block;padding:8px 18px;background:#388e3c;
                     color:#fff;border-radius:6px;text-decoration:none;font-size:14px">
                     Открыть в приложении</a>
                </div>""")
        body = "".join(rows)
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VLESS Config</title>
<style>
 body{{font-family:-apple-system,sans-serif;background:#f0f4f8;padding:16px;margin:0}}
 .card{{background:#fff;border-radius:14px;padding:20px;margin-bottom:16px;
        box-shadow:0 2px 10px rgba(0,0,0,.08);text-align:center}}
 h1{{font-size:20px;color:#333;margin-bottom:4px}}
 h3{{color:#555;margin:0 0 12px}}
 .warn{{color:#c62828;font-size:13px;margin-bottom:16px}}
</style></head>
<body>
<h1>🔐 VLESS Config</h1>
<p class="warn">⚠️ Одноразовая ссылка — страница недоступна после этого просмотра</p>
{body}
<p style="font-size:11px;color:#aaa;text-align:center;margin-top:20px">
 Chimera Project</p>
</body></html>"""

    html_content = _make_html()
    served_once  = [False]
    stop_event   = threading.Event()

    class _OneTimeHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            parsed    = urllib.parse.urlparse(self.path)
            params    = urllib.parse.parse_qs(parsed.query)
            req_token = params.get("t", [""])[0]
            if req_token != token:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"403 Forbidden")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html_content.encode())
            served_once[0] = True
            stop_event.set()

    server = http.server.HTTPServer(("0.0.0.0", share_port), _OneTimeHandler)
    server.timeout = 1
    share_url = f"http://{server_ip}:{share_port}/?t={token}"

    _box_row(f"  {GREEN}Сервер запущен на порту {share_port}{NC}")
    _box_row(f"  Ссылка (5 минут или 1 просмотр):")
    _box_row(f"  {CYAN}{BOLD}{share_url}{NC}")

    _run(["ufw", "allow", str(share_port), "comment", "xray-share-tmp"],
         check=False, quiet=True)
    _box_info("Ожидание подключения (5 минут)...")
    _box_row(f"  {DIM}(Ctrl+C для отмены){NC}")
    _box_bottom()

    deadline = time.time() + 300
    try:
        while not stop_event.is_set() and time.time() < deadline:
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _run(["ufw", "delete", "allow", str(share_port)], check=False, quiet=True)

    if served_once[0]:
        success("Конфиг передан. Сервер закрыт.")
    else:
        warn("Время истекло — сервер закрыт без отдачи страницы.")
    log_to_file("INFO", f"Share config: served={served_once[0]}, port={share_port}")
