"""
chimera/modules/reconfigure.py
───────────────────────────────────────────────────────────────────────────────
[R] Смена домена / порта без полной переустановки Xray.

Содержит:
  • ``do_reconfigure()`` — интерактивная смена домена и/или порта:
      - получает/проверяет SSL-сертификат Let's Encrypt (для xhttp-TLS);
      - патчит Xray ``config.json`` (порт + TLS-сертификаты + Stats API);
      - патчит nginx ``*.conf`` (домен + listen-порты);
      - обновляет UFW (открывает новый порт, закрывает старый);
      - перезаписывает ``state.json`` и мутирует глобальные переменные
        ``PARAM_DOMAIN``/``SERVER_PORT``/``XHTTP_PORT``/``PROTOCOL_MODE``
        в ``chimera._core``.

Точки входа из _core.py:
    from chimera.modules.reconfigure import do_reconfigure

Глобалы ядра мутируются через ``setattr(core, "PARAM_DOMAIN", new_domain)``
и т.п. — это preserves ту же семантику, что и ``global X; X = value``,
поскольку ``_core`` — это сам модуль ядра.

Доступ к helpers ядра (``_box_*``, ``_run``, ``warn``/``info``/``success``,
ANSI-цвета, ``STATE_FILE``, ``CONFIG_DIR``, ``NGINX_CONF_DIR``, ``XRAY_BIN``,
``_apply_stats_to_config``, ``log_to_file``) — через importlib.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import time
from pathlib import Path


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  [R] СМЕНА ДОМЕНА/ПОРТА БЕЗ ПЕРЕУСТАНОВКИ
# =============================================================================
def do_reconfigure() -> None:
    """Смена домена или порта без полной переустановки."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    _box_warn   = core._box_warn
    _run = core._run
    _apply_stats_to_config = core._apply_stats_to_config
    warn    = core.warn
    info    = core.info
    success = core.success
    log_to_file = core.log_to_file
    STATE_FILE    = core.STATE_FILE
    CONFIG_DIR    = core.CONFIG_DIR
    NGINX_CONF_DIR = core.NGINX_CONF_DIR
    XRAY_BIN      = core.XRAY_BIN
    CYAN   = core.CYAN
    NC     = core.NC
    YELLOW = core.YELLOW
    DIM    = core.DIM
    GREEN  = core.GREEN

    print()
    print()
    _box_top(f"Реконфигурация домена / порта")

    if not STATE_FILE.exists():
        _box_warn("state.json не найден — сначала выполните установку (пункт 1)")
        return

    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _box_warn(f"Не удалось прочитать state.json: {e}")
        return

    old_domain = state.get("domain", "?")
    old_port   = state.get("server_port", 443)
    proto      = state.get("protocol_mode", "reality")
    setattr(core, "PROTOCOL_MODE", proto)

    _box_row(f"  Текущий домен: {CYAN}{old_domain}{NC}")
    _box_row(f"  Текущий порт:  {CYAN}{old_port}{NC}")
    _box_row(f"  Протокол:      {CYAN}{proto}{NC}")
    _box_item("1", f"Сменить домен")
    _box_item("2", f"Сменить порт")
    _box_item("3", f"Сменить домен и порт")
    _box_item("Q", f"Назад")
    _box_bottom()
    ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    if ch not in ("1", "2", "3"):
        return

    new_domain = old_domain
    new_port   = old_port

    if ch in ("1", "3"):
        raw = input(f"  Новый домен [{old_domain}]: ").strip()
        if raw:
            new_domain = raw

    if ch in ("2", "3"):
        raw = input(f"  Новый порт [{old_port}]: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            new_port = int(raw)
        else:
            warn("Некорректный порт — оставляем прежний")

    #  FIX: если параметры не изменились — предлагаем принудительную
    # реконфигурацию. Это нужно когда предыдущая смена домена прошла
    # криво (SNI не обновился, сертификат не получен, и т.д.) и
    # пользователь хочет «переприменить» с тем же доменом.
    force_reapply = False
    if new_domain == old_domain and new_port == old_port:
        _box_top("Параметры не изменились")
        _box_row(f"  {YELLOW}Домен и порт те же, но вы можете запустить{NC}")
        _box_row(f"  {YELLOW}принудительную реконфигурацию — это обновит{NC}")
        _box_row(f"  {YELLOW}SNI, сертификат, nginx и клиентские ссылки.{NC}")
        _box_row()
        _box_row(f"  {DIM}Полезно если предыдущая смена домена прошла криво.{NC}")
        _box_bottom()
        ans = input(f"  {CYAN}Принудительная реконфигурация? [y/N]:{NC} ").strip().lower()
        if ans != "y":
            return
        force_reapply = True

    info(f"Применяем: домен={new_domain}, порт={new_port}"
         f"{' (принудительно)' if force_reapply else ''}")

    # --- SSL-сертификат (для любого протокола если домен сменился или force) ---
    if new_domain != old_domain or force_reapply:
        info(f"Получаем/обновляем SSL-сертификат для {new_domain}...")
        certbot_bin = (Path("/snap/bin/certbot") if Path("/snap/bin/certbot").exists()
                       else Path("/usr/bin/certbot"))
        if not certbot_bin.exists():
            warn("certbot не найден — сертификат нужно получить вручную")
        else:
            _run(["systemctl", "stop", "nginx"], check=False, quiet=True)
            r = _run([
                str(certbot_bin), "certonly", "--standalone",
                "-d", new_domain,
                "--non-interactive", "--agree-tos",
                "-m", f"admin@{new_domain}",
                "--keep-until-expiring"
            ], check=False)
            if r.returncode != 0:
                warn("certbot завершился с ошибкой — домен возможно недоступен")
                ans = input("  Продолжить всё равно? [y/N]: ").strip().lower()
                if ans != "y":
                    _run(["systemctl", "start", "nginx"], check=False, quiet=True)
                    return
            _run(["systemctl", "start", "nginx"], check=False, quiet=True)

        #  FIX: Показываем список ВСЕХ сертификатов Let's Encrypt
        # и предлагаем выбрать какие удалить. Раньше искали только
        # old_domain, но сертификатов может быть несколько (старые
        # домены, тестовые, и т.д.).
        try:
            r_certs = _run([str(certbot_bin), "certificates"],
                           capture=True, check=False, quiet=True)
            if r_certs.returncode == 0 and r_certs.stdout.strip():
                # Парсим имена сертификатов
                cert_names = []
                for line in r_certs.stdout.splitlines():
                    # Формат: "  Certificate Name: example.com\n    Domains: ..."
                    if "Certificate Name:" in line:
                        name = line.split("Certificate Name:")[1].strip()
                        if name:
                            cert_names.append(name)
                if cert_names:
                    print()
                    _box_top("Сертификаты Let's Encrypt")
                    _box_row(f"  {DIM}Найдено сертификатов: {len(cert_names)}{NC}")
                    _box_sep()
                    for i, cn in enumerate(cert_names, 1):
                        # Помечаем текущий домен и старый домен
                        marker = ""
                        if cn == new_domain:
                            marker = f"  {GREEN}← текущий{NC}"
                        elif cn == old_domain:
                            marker = f"  {YELLOW}← старый домен{NC}"
                        _box_row(f"  {DIM}{i}{NC}  {CYAN}{cn}{NC}{marker}")
                    _box_sep()
                    _box_row(f"  {DIM}Введите номера через запятую для удаления.{NC}")
                    _box_row(f"  {DIM}Enter — пропустить. 'old' — удалить все кроме текущего.{NC}")
                    _box_bottom()
                    del_input = input(f"  {CYAN}Удалить сертификаты:{NC} ").strip().lower()
                    to_delete = set()
                    if del_input == "old":
                        # Удалить все кроме new_domain
                        to_delete = {cn for cn in cert_names if cn != new_domain}
                    elif del_input:
                        for token in del_input.replace(",", " ").split():
                            if token.isdigit() and 1 <= int(token) <= len(cert_names):
                                to_delete.add(cert_names[int(token) - 1])
                    if to_delete:
                        for cert_name in to_delete:
                            r_del = _run([str(certbot_bin), "delete",
                                          "--cert-name", cert_name,
                                          "--non-interactive"],
                                         check=False, quiet=True)
                            if r_del.returncode == 0:
                                success(f"Сертификат удалён: {cert_name}")
                            else:
                                warn(f"Не удалось удалить {cert_name}")
                    else:
                        info("Удаление сертификатов пропущено")
        except Exception as e:
            warn(f"Не удалось получить список сертификатов: {e}")

    # --- Патч Xray config.json ---
    patched_xray = False
    for cfg_path in (Path("/usr/local/etc/xray/config.json"), CONFIG_DIR / "config.json"):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            for ib in cfg.get("inbounds", []):
                if ib.get("port") == old_port:
                    ib["port"] = new_port
                #  FIX: Обновляем SNI/serverNames при смене домена.
                # Раньше это НЕ делалось — клиент подключался с новым SNI,
                # а сервер ожидал старый → миллион ошибок в секунду.
                ss = ib.get("streamSettings", {})
                if new_domain != old_domain or force_reapply:
                    # REALITY: ПОЛНОСТЬЮ перезаписываем serverNames на new_domain.
                    # Раньше делали точечный replace (old_domain → new_domain),
                    # но это не работало если в serverNames лежал домен от
                    # ЕЩЁ более старой смены (не совпадающий с old_domain из
                    # state.json). Теперь — перезаписываем весь список.
                    rs = ss.get("realitySettings", {})
                    if rs:
                        old_sni_list = rs.get("serverNames", [])
                        rs["serverNames"] = [new_domain]
                        info(f"REALITY serverNames: {old_sni_list} → [{new_domain}]")
                    # xHTTP TLS: обновляем SNI + пути к сертификатам
                    tls = ss.get("tlsSettings", {})
                    if tls:
                        # SNI — перезаписываем полностью
                        tls["serverName"] = new_domain
                        # Сертификаты
                        cert_dir = Path(f"/etc/letsencrypt/live/{new_domain}")
                        if cert_dir.exists():
                            tls["certificates"] = [{
                                "certificateFile": str(cert_dir / "fullchain.pem"),
                                "keyFile":         str(cert_dir / "privkey.pem"),
                            }]
                        info(f"xHTTP TLS SNI/сертификаты: → {new_domain}")
            # Гарантируем наличие Stats API секций (statsUserUplink/Downlink)
            _apply_stats_to_config(cfg)
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            cfg_path.chmod(0o640)
            patched_xray = True
            info(f"Xray конфиг обновлён: {cfg_path}")
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    # --- Патч Nginx ---
    if new_domain != old_domain or force_reapply:
        for conf in NGINX_CONF_DIR.glob("*.conf"):
            try:
                text = conf.read_text()
                changed = False
                if new_domain != old_domain or force_reapply:
                    #  FIX: при force_reapply или смене домена — перезаписываем
                    # ВСЕ домены в nginx конфиге на new_domain. Раньше делали
                    # точечный replace (old_domain → new_domain), но это не
                    # работало если в конфиге был домен от ЕЩЁ более старой
                    # смены (не совпадающий с old_domain из state.json).
                    # Теперь: ищем server_name и ssl_certificate пути,
                    # заменяем на new_domain.
                    import re as _re
                    # server_name: заменяем все домены на new_domain
                    text2 = _re.sub(
                        r'(server_name\s+)[^;]+;',
                        rf'\g<1>{new_domain};',
                        text
                    )
                    # ssl_certificate: заменяем пути к сертификатам
                    cert_dir_new = f"/etc/letsencrypt/live/{new_domain}"
                    text2 = _re.sub(
                        r'(ssl_certificate\s+).*?/letsencrypt/live/[^/]+/',
                        rf'\g<1>{cert_dir_new}/',
                        text2
                    )
                    text2 = _re.sub(
                        r'(ssl_certificate_key\s+).*?/letsencrypt/live/[^/]+/',
                        rf'\g<1>{cert_dir_new}/',
                        text2
                    )
                    if text2 != text:
                        text = text2
                        changed = True
                if new_port != old_port:
                    text2 = text.replace(f"listen {old_port}", f"listen {new_port}")
                    text2 = text2.replace(f"listen [::]:{old_port}", f"listen [::]:{new_port}")
                    if text2 != text:
                        text = text2
                        changed = True
                if changed:
                    conf.write_text(text)
                    info(f"Nginx конфиг обновлён: {conf}")
            except Exception as e:
                warn(f"Ошибка патча nginx {conf}: {e}")

    # --- UFW: открыть новый порт, закрыть старый ---
    #  миграция на port_registry (с backward compat для legacy comments).
    if new_port != old_port:
        _vless_reconfigure_ufw_port_change(core, new_port, old_port)

    # --- Обновить state.json ---
    try:
        state["domain"]      = new_domain
        state["server_port"] = new_port
        #  FIX: обновляем reality_dest если это НЕ AWG (там чужой домен).
        # Для обычного REALITY reality_dest = "" (не используется),
        # serverNames = PARAM_DOMAIN. Для AWG reality_dest = чужой домен
        # (cloudflare.com и т.д.) — его НЕ меняем.
        _awg_enabled = state.get("awg_exit_enabled", False)
        if not _awg_enabled:
            # Обычный REALITY: serverNames = домен сервера
            # reality_dest не используется (пустой), но обновляем на всякий случай
            if state.get("reality_dest", "") == old_domain:
                state["reality_dest"] = new_domain
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        setattr(core, "PARAM_DOMAIN", new_domain)
        setattr(core, "SERVER_PORT",  new_port)
        setattr(core, "XHTTP_PORT",   new_port)
    except Exception as e:
        warn(f"Не удалось обновить state.json: {e}")

    # --- Перезапуск ---
    if patched_xray:
        val = _run([str(XRAY_BIN), "-test", "-config",
                    "/usr/local/etc/xray/config.json"],
                   capture=True, check=False, quiet=True)
        if val.returncode != 0:
            warn("Xray конфиг невалиден! Проверьте вручную.")
            warn((val.stdout + val.stderr)[:300])
        else:
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
            _run(["systemctl", "restart", "xray"], check=False, quiet=True)
            time.sleep(2)
            success(f"Реконфигурация завершена: домен={new_domain}, порт={new_port}")
            #  FIX: перегенерируем клиентские ссылки с новым доменом/SNI.
            # Раньше ссылки не обновлялись — пользователи оставались со
            # старыми ссылками, которые не работали с новым доменом.
            try:
                from chimera.modules.users_manager import generate_client_links
                generate_client_links()
                success("Клиентские ссылки перегенерированы с новым доменом")
            except Exception as e:
                warn(f"Не удалось перегенерировать ссылки: {e}")
                warn("Сгенерируйте вручную: меню → Пользователи → [3] Показать ссылку")
    log_to_file("INFO", f"Reconfigure: {old_domain}:{old_port} → {new_domain}:{new_port}")


#  helper для смены UFW-порта при reconfigure VLESS.
# Использует port_registry с backward compat для legacy comments:
#   - "VLESS reconfigure" (старый comment от reconfigure.py)
#   - "SSH" (от network_setup.py)
#   - "HTTP (certbot ACME)" (от network_setup.py)
#   - "VLESS REALITY :443" / "VLESS XHTTP :443" и т.п. (от network_setup.py)
# Это гарантирует что старые UFW-правила будут найдены и закрыты при смене порта.
def _vless_reconfigure_ufw_port_change(core, new_port: int, old_port: int) -> None:
    """Открывает new_port, закрывает old_port в UFW через port_registry.

    legacy_comments покрывает все варианты comment, которые могли быть
    созданы network_setup.py или предыдущими версиями reconfigure.py.
    """
    _run = core._run
    _LEGACY_COMMENTS = [
        "VLESS reconfigure",
        "SSH",
        "HTTP (certbot ACME)",
        "VLESS",
    ]
    # 1. Открываем новый порт.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register, ufw_close_port, port_unregister,
            SERVICE_VLESS,
        )
        port_register(SERVICE_VLESS, new_port, "tcp",
                      comment=f"VLESS (reconfigured to :{new_port})",
                      force=True)
        ok, msg = ufw_open_port(new_port, "tcp", SERVICE_VLESS,
                                comment=f"VLESS (reconfigured to :{new_port})")
        if not ok:
            # Fallback на прямой ufw allow.
            _run(["ufw", "allow", str(new_port), "comment", "VLESS reconfigure"],
                 check=False, quiet=True)
        # 2. Закрываем старый порт (с legacy comments для backward compat).
        ufw_close_port(old_port, "tcp", SERVICE_VLESS,
                       legacy_comments=_LEGACY_COMMENTS)
        port_unregister(SERVICE_VLESS, old_port, "tcp")
    except Exception:
        # Fallback: старый код (прямой ufw allow/delete).
        _run(["ufw", "allow", str(new_port), "comment", "VLESS reconfigure"],
             check=False, quiet=True)
        _run(["ufw", "delete", "allow", str(old_port)],
             check=False, quiet=True)
