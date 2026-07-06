"""
vless_installer/modules/reconfigure.py
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
        в ``vless_installer._core``.

Точки входа из _core.py:
    from vless_installer.modules.reconfigure import do_reconfigure

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
    """Возвращает модуль vless_installer._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  [R] СМЕНА ДОМЕНА/ПОРТА БЕЗ ПЕРЕУСТАНОВКИ
# =============================================================================
def do_reconfigure() -> None:
    """Смена домена или порта без полной переустановки."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
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
    CYAN = core.CYAN
    NC   = core.NC

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

    if new_domain == old_domain and new_port == old_port:
        warn("Параметры не изменились — выход")
        return

    info(f"Применяем: домен={new_domain}, порт={new_port}")

    # --- SSL-сертификат (только для xHTTP TLS и если домен сменился) ---
    if proto == "xhttp" and new_domain != old_domain:
        info(f"Получаем SSL-сертификат для {new_domain}...")
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
            # Патч TLS-сертификата если нужно
            if proto == "xhttp" and new_domain != old_domain:
                for ib in cfg.get("inbounds", []):
                    tls = (ib.get("streamSettings", {})
                             .get("tlsSettings", {}))
                    if tls:
                        cert_dir = Path(f"/etc/letsencrypt/live/{new_domain}")
                        tls["certificates"] = [{
                            "certificateFile": str(cert_dir / "fullchain.pem"),
                            "keyFile":         str(cert_dir / "privkey.pem"),
                        }]
            # Гарантируем наличие Stats API секций (statsUserUplink/Downlink)
            _apply_stats_to_config(cfg)
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            cfg_path.chmod(0o640)
            patched_xray = True
            info(f"Xray конфиг обновлён: {cfg_path}")
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    # --- Патч Nginx ---
    if new_domain != old_domain or new_port != old_port:
        for conf in NGINX_CONF_DIR.glob("*.conf"):
            try:
                text = conf.read_text()
                changed = False
                if new_domain != old_domain:
                    text2 = text.replace(old_domain, new_domain)
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
    if new_port != old_port:
        _run(["ufw", "allow", str(new_port), "comment", "VLESS reconfigure"],
             check=False, quiet=True)
        _run(["ufw", "delete", "allow", str(old_port)],
             check=False, quiet=True)

    # --- Обновить state.json ---
    try:
        state["domain"]      = new_domain
        state["server_port"] = new_port
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
    log_to_file("INFO", f"Reconfigure: {old_domain}:{old_port} → {new_domain}:{new_port}")
