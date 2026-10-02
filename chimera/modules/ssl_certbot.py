"""
chimera/modules/ssl_certbot.py
───────────────────────────────────────────────────────────────────────────────
SSL / certbot: получение сертификата Let's Encrypt, фикс прав, автообновление,
мониторинг certbot renew + алёрт.

Содержит 4 логические части (объединены, т.к. все работают с SSL-сертификатами):

1. **obtain_ssl_cert()** — интерактивный выпуск сертификата Let's Encrypt
   через certbot --webroot (с fallback на самоподписанный).
2. **fix_letsencrypt_permissions(domain)** — выставляет права на сертификаты
   так, чтобы пользователь xray мог их читать (root:xray 640/644).
3. **ensure_cert_fix_script(domain)** + **setup_cert_renewal()** — создает
   systemd-хук и crontab для автообновления сертификата certbot renew.
4. **Certbot monitor** — cron-задача дважды в день: certbot renew + проверка
   срока + Telegram-алёрт. Управляется через do_manage_certbot_monitor().

Точки входа из _core.py:
    from chimera.modules.ssl_certbot import (
        _CERTBOT_MONITOR_CRON, _CERTBOT_MONITOR_SCRIPT,
        obtain_ssl_cert, fix_letsencrypt_permissions,
        ensure_cert_fix_script, setup_cert_renewal,
        _certbot_renew_and_notify, _certbot_install_monitor_cron,
        do_manage_certbot_monitor,
    )

Доступ к helpers ядра (_run, _box_*, цвета, log_to_file, _tg_notify_event,
_log_change, STATE_FILE, PARAM_*) — через importlib (lazy binding), как и в
других извлечённых модулях (asn_cache.py, standalone_screens.py, geo_files.py).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import grp
import time
import textwrap
from pathlib import Path
from typing import Optional

# ── Константы ─────────────────────────────────────────────────────────────────
_CERTBOT_MONITOR_CRON    = Path("/etc/cron.d/xray-certbot-monitor")
_CERTBOT_MONITOR_SCRIPT  = Path("/usr/local/bin/xray-certbot-monitor.sh")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules (был импортиро­ван
    одним из поздних lazy-вызовов внутри других модулей) — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
# УСТОЙЧИВАЯ ПРОВЕРКА DNS + ЗАЩИТА ВАЛИДНОГО LE-СЕРТИФИКАТА
# =============================================================================
def _dig_a_records(server: str, domain: str) -> list:
    """A-записи domain через указанный DNS-сервер (dig, короткий таймаут).

    +time=3 +tries=1 — dig сам ограничивает время (локальный резолвер в
    середине установки может бутстрапиться дольше; не вешаем установку).
    """
    core = _core_module()
    try:
        r = core._run(
            ["dig", "+short", "+time=3", "+tries=1", f"@{server}", domain, "A"],
            capture=True, check=False)
        return [x for x in (r.stdout or "").strip().split()
                if x and not x.endswith(".")]
    except Exception:
        return []


def domain_points_to_server(domain: str, ipv4: str) -> "tuple[bool, str]":
    """Резолвит domain и проверяет, что среди A-записей есть ipv4.

    Инцидент (server-ru, 203.0.113.102): единственный dig через
    системный резолвер (127.0.0.1 = DNSCrypt, который установщик только
    что перезапустил: кэш холодный, DoH-upstream ещё бутстрапится) давал
    таймаут → ЛОЖНЫЙ «домен НЕ резолвится», хотя nslookup через 1.1.1.1
    отвечал мгновенно. Проверяем по нескольким независимым путям:
      1) локальный резолвер — dig @127.0.0.1, 2 попытки с паузой 2с
         (DNSCrypt поднимается не мгновенно);
      2) getaddrinfo — системный путь, работает даже без dig;
      3) внешние резолверы 1.1.1.1 / 8.8.8.8 / 77.88.8.8 напрямую
         (полностью обходят локальный DNSCrypt; LE валидирует так же —
         из интернета, не через наш резолвер).
    Возвращает (True, источник) если хоть один путь подтвердил IP.
    """
    # 1) локальный резолвер ×2 (DNSCrypt мог только что стартовать)
    if ipv4 in _dig_a_records("127.0.0.1", domain):
        return True, "локальный резолвер"
    time.sleep(2)
    if ipv4 in _dig_a_records("127.0.0.1", domain):
        return True, "локальный резолвер"
    # 2) системный резолвер без dig (getaddrinfo, только IPv4)
    try:
        import socket
        got = {x[4][0] for x in
               socket.getaddrinfo(domain, None, socket.AF_INET)}
        if ipv4 in got:
            return True, "getaddrinfo"
    except Exception:
        pass
    # 3) внешние резолверы — независимый источник истины
    for ext in ("1.1.1.1", "8.8.8.8", "77.88.8.8"):
        if ipv4 in _dig_a_records(ext, domain):
            return True, ext
    return False, ""


def existing_cert_status(cert_path: Path) -> "tuple[bool, bool, int, str, str]":
    """Состояние сертификата на диске.

    Возвращает (exists, self_signed, days_left, expiry_str, issuer_str).
    self_signed=True — сертификат сгенерирован нами (маркер O=SelfSigned
    из generate_self_signed_cert) либо issuer совпадает с subject.
    """
    if not cert_path.exists():
        return False, False, 0, "", ""
    core = _core_module()
    _run = core._run
    issuer = subject = expiry = ""
    try:
        r = _run(["openssl", "x509", "-noout", "-issuer", "-subject",
                  "-enddate", "-in", str(cert_path)],
                 capture=True, check=False)
        for line in (r.stdout or "").splitlines():
            if line.startswith("issuer="):
                issuer = line.split("=", 1)[1].strip()
            elif line.startswith("subject="):
                subject = line.split("=", 1)[1].strip()
            elif line.startswith("notAfter="):
                expiry = line.split("=", 1)[1].strip()
    except Exception:
        pass
    self_signed = ("SelfSigned" in issuer) or (issuer != "" and issuer == subject)
    days_left = 0
    if expiry:
        try:
            r2 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
            days_left = (int(r2.stdout.strip()) - int(time.time())) // 86400
        except Exception:
            days_left = 0
    return True, self_signed, days_left, expiry, issuer


# =============================================================================
#  ВЫПУСК СЕРТИФИКАТА LET'S ENCRYPT
# =============================================================================
def obtain_ssl_cert(domain: Optional[str] = None) -> None:
    """Получение SSL-сертификата Let's Encrypt для PARAM_DOMAIN (с fallback).

    Если domain передан явно — сертификат выпускается для этого домена (а не
    для core.PARAM_DOMAIN). Используется в Telemt nginx-fallback, где домен
    Telemt-маскировки может отличаться от основного VLESS-домена сервера.

    Если domain не передан — поведение идентично предыдущему (VLESS install
    flow не меняется ни в одном байте вывода).
    """
    core = _core_module()
    info    = core.info
    warn    = core.warn
    success = core.success
    _run    = core._run
    die     = core.die
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    get_server_ip          = core.get_server_ip
    generate_self_signed_cert = core.generate_self_signed_cert
    PARAM_DOMAIN = domain if domain is not None else core.PARAM_DOMAIN
    PARAM_EMAIL  = core.PARAM_EMAIL
    PROTOCOL_MODE = core.PROTOCOL_MODE
    CYAN, NC, GREEN, RED, YELLOW = core.CYAN, core.NC, core.GREEN, core.RED, core.YELLOW
    # fix_letsencrypt_permissions — модуль-локальная (см. ниже)
    info(f"Получение SSL-сертификата для {PARAM_DOMAIN}...")
    # === Проверка DNS перед получением сертификата (устойчивая) ===
    # Один dig через системный резолвер давал ЛОЖНЫЙ WARN, когда локальный
    # DNSCrypt ещё бутстрапился (инцидент). Теперь: локальный (2 попытки)
    # → getaddrinfo → внешние 1.1.1.1/8.8.8.8/77.88.8.8. WARN только если
    # НЕ резолвится НИГДЕ — тогда certbot действительно упадёт.
    ipv4 = get_server_ip("4")
    if ipv4:
        dns_ok, dns_via = domain_points_to_server(PARAM_DOMAIN, ipv4)
        if dns_ok:
            if dns_via not in ("локальный резолвер", "getaddrinfo"):
                info(f"DNS подтверждён через {dns_via} "
                     f"(локальный резолвер ещё стартует)")
        else:
            warn(f"Домен {PARAM_DOMAIN} НЕ резолвится в IP сервера ({ipv4}) "
                 f"ни локально, ни через внешние резолверы!")
            warn("Это может привести к ошибке certbot.")
            if input(f"{YELLOW}Продолжить всё равно? [y/N]:{NC} ").strip().lower() != 'y':
                die("DNS не настроен корректно. Исправьте A-запись и запустите заново.")

    cert_path = Path(f"/etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem")
    key_path  = Path(f"/etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem")
    web_root  = Path(f"/var/www/{PARAM_DOMAIN}")
    request_new = True
    user_reissue = False # явный «R» от пользователя → --force-renewal

    if cert_path.exists() and key_path.exists():
        # единый разбор статуса (issuer + срок) — показывает в боксе,
        # КЕМ выдан сертификат, и подсказывает верный выбор по умолчанию:
        # самоподпис → перевыпустить (R), валидный LE → использовать (U).
        _ex, _selfsigned, days_left, expiry, _issuer = \
            existing_cert_status(cert_path)
        if not expiry:
            expiry = "unknown"

        print()
        _box_top("Найден существующий сертификат")
        _box_row()
        if _selfsigned:
            _box_row(f"  Кем выдан:  {RED}САМОПОДПИСАННЫЙ{NC} — рекомендуем перевыпустить")
        elif "Encrypt" in _issuer:
            _box_row(f"  Кем выдан:  {GREEN}Let's Encrypt{NC}")
        elif _issuer:
            _box_row(f"  Кем выдан:  {CYAN}{_issuer}{NC}")
        _box_row(f"  Истекает: {CYAN}{expiry}{NC}")
        color = GREEN if days_left > 0 else RED
        label = f"{days_left} дней" if days_left > 0 else "ИСТЁК"
        _box_row(f"  Осталось: {color}{label}{NC}")
        _box_row()
        _box_item("U", f"Использовать имеющийся")
        _box_item("R", f"Перевыпустить новый")
        _box_sep()
        _box_bottom()
        default_choice = "r" if _selfsigned else "u"
        while True:
            choice = input("  Выбор [U/R]: ").strip().lower() or default_choice
            if choice == "u":
                request_new = False
                success("Используется существующий сертификат")
                break
            elif choice == "r":
                request_new = True
                user_reissue = True
                info("Будет выпущен новый сертификат")
                break
            warn("Введите U или R")

    if request_new:
        info("Выпуск сертификата Let's Encrypt...")
        web_root.mkdir(parents=True, exist_ok=True)
        (web_root / "index.html").write_text("<h1>ACME Verification</h1>")

        le_ok = False
        # --force-renewal ТОЛЬКО при явном «R» от пользователя.
        # Раньше флаг был безусловным: каждый повторный запуск установки
        # принуждал certbot к новому выпуску → исчерпывался лимит LE
        # «5 дублей за 7 дней» (инцидент). Без флага certbot на
        # валидном сертификате отвечает «not yet due for renewal»
        # (exit 0) и НЕ трогает его — установка идемпотентна.
        certbot_cmd = [
            "certbot", "certonly", "--webroot",
            "--webroot-path", str(web_root),
            "--non-interactive", "--agree-tos",
            "--email", PARAM_EMAIL,
            "-d", PARAM_DOMAIN,
        ]
        if user_reissue:
            certbot_cmd.append("--force-renewal")
        r = _run(certbot_cmd, capture=True, check=False)
        if r.returncode == 0:
            success("Сертификат Let's Encrypt успешно выпущен")
            le_ok = True

        if not le_ok:
            # certbot упал (rate-limit, недоступность :80 и т.п.)
            # если на диске есть ВАЛИДНЫЙ НЕсамоподписанный сертификат,
            # используем его. Раньше здесь безусловно генерировался
            # самоподписанный, который ЗАТИРАЛ живой LE-сертификат:
            # openssl писал прямо в /etc/letsencrypt/live/<domain>/, а у
            # certbot это СИМЛИНКИ в archive/ — сертификат погибал
            # безвозвратно, до конца срока действия.
            _ex2, _ss2, _days2, _exp2, _ = existing_cert_status(cert_path)
            if _ex2 and not _ss2 and _days2 > 0:
                warn("certbot не смог выпустить сертификат (подробности: "
                     "/var/log/letsencrypt/letsencrypt.log)")
                success(f"Найден валидный сертификат (истекает {_exp2}) — "
                        f"используем его, самоподписанный НЕ генерируем")
            else:
                warn("Не удалось получить сертификат LE — генерируем самоподписанный")
                generate_self_signed_cert(PARAM_DOMAIN)

        if not cert_path.exists():
            warn(f"Сертификат не найден по пути {cert_path} — проверьте DNS и порт 80.")
            warn("Установка продолжается, но HTTPS может не работать.")
            warn(f"Для перевыпуска: certbot certonly --webroot -w {web_root} -d {PARAM_DOMAIN}")
        else:
            success(f"Сертификат на месте: {cert_path}")

    # xHTTP TLS: Xray читает сертификаты напрямую — выставляем права
    if PROTOCOL_MODE == "xhttp" and cert_path.exists():
        fix_letsencrypt_permissions(PARAM_DOMAIN)


def fix_letsencrypt_permissions(domain: str) -> None:
    """Выставляет права на сертификаты так, чтобы пользователь xray мог их читать."""
    core = _core_module()
    warn    = core.warn
    success = core.success
    CYAN, NC, GREEN, RED, YELLOW = core.CYAN, core.NC, core.GREEN, core.RED, core.YELLOW
    import os, grp
    archive_dir     = Path(f"/etc/letsencrypt/archive/{domain}")
    live_domain_dir = Path(f"/etc/letsencrypt/live/{domain}")

    if not archive_dir.exists():
        warn(f"fix_letsencrypt_permissions: {archive_dir} не найден — пропускаем")
        return

    # Гарантируем права на проход по директориям (execute bit).
    # live/<domain> НЕ создаём через mkdir — эта директория принадлежит certbot.
    for d in (Path("/etc/letsencrypt/live"), live_domain_dir,
              Path("/etc/letsencrypt/archive"), archive_dir):
        try:
            if d.exists():
                d.chmod(0o755)
        except Exception as e:
            warn(f"Ошибка установки прав на {d}: {e}")

    # Получаем GID группы xray один раз
    try:
        xray_gid = grp.getgrnam('xray').gr_gid
        has_xray = True
    except KeyError:
        has_xray = False

    # privkey*.pem → 640 root:xray (только xray может читать приватный ключ)
    for f_path in archive_dir.glob("privkey*.pem"):
        try:
            if has_xray:
                os.chown(str(f_path), 0, xray_gid)
            os.chmod(str(f_path), 0o640)
        except Exception as e:
            warn(f"Не удалось исправить права для {f_path}: {e}")

    # fullchain/chain/cert → 644 root:root (публичные — читает nginx, xray и все)
    for pattern in ("fullchain*.pem", "chain*.pem", "cert*.pem"):
        for f_path in archive_dir.glob(pattern):
            try:
                os.chmod(str(f_path), 0o644)
            except Exception as e:
                warn(f"Не удалось исправить права для {f_path}: {e}")

    success(f"Права на сертификаты для {domain} обновлены "
            f"({'root:xray 640/644' if has_xray else '644 для всех'})")


# =============================================================================
#  АВТООБНОВЛЕНИЕ СЕРТИФИКАТА (systemd-хук + crontab)
# =============================================================================
def ensure_cert_fix_script(domain: str) -> Path:
    """Создает внешний скрипт для исправления прав, вызываемый systemd перед стартом Xray."""
    script_path = Path("/usr/local/bin/fix-xray-certs.sh")
    script_content = f"""#!/bin/bash
# Автоматический фикс прав для Xray xHTTP TLS (Created by install.py)
DOMAIN="{domain}"
ARCHIVE_DIR="/etc/letsencrypt/archive/$DOMAIN"
LIVE_DIR="/etc/letsencrypt/live/$DOMAIN"

[[ ! -d "$ARCHIVE_DIR" ]] && exit 0

# Гарантируем права на проход по директориям
chmod 755 /etc/letsencrypt/live 2>/dev/null || true
chmod 755 "$LIVE_DIR" 2>/dev/null || true
chmod 755 /etc/letsencrypt/archive 2>/dev/null || true
chmod 755 "$ARCHIVE_DIR" 2>/dev/null || true

# privkey → 640 root:xray (только xray читает приватный ключ)
chown root:xray "$ARCHIVE_DIR"/privkey*.pem 2>/dev/null || true
chmod 640 "$ARCHIVE_DIR"/privkey*.pem 2>/dev/null || true

# Публичные сертификаты → 644 (читают все: xray, nginx, etc.)
chmod 644 "$ARCHIVE_DIR"/fullchain*.pem 2>/dev/null || true
chmod 644 "$ARCHIVE_DIR"/chain*.pem 2>/dev/null || true
chmod 644 "$ARCHIVE_DIR"/cert*.pem 2>/dev/null || true
"""
    script_path.write_text(script_content)
    script_path.chmod(0o750)
    return script_path


def setup_cert_renewal() -> None:
    core = _core_module()
    success = core.success
    _run    = core._run
    PROTOCOL_MODE = core.PROTOCOL_MODE
    PARAM_DOMAIN  = core.PARAM_DOMAIN
    deploy_dir = Path("/etc/letsencrypt/renewal-hooks/deploy")
    deploy_dir.mkdir(parents=True, exist_ok=True)
    hook = deploy_dir / "nginx-reload.sh"

    if PROTOCOL_MODE == "xhttp":
        # Хук восстанавливает права после certbot renew и перезапускает сервисы.
        # privkey → 640 root:xray, публичные сертификаты → 644 (для xray и nginx).
        hook.write_text(textwrap.dedent(f"""\
#!/bin/bash
# Автоматически создаётся установщиком VLESS xHTTP TLS
DOMAIN="{PARAM_DOMAIN}"
ARCHIVE_DIR="/etc/letsencrypt/archive/$DOMAIN"

[[ ! -d "$ARCHIVE_DIR" ]] && exit 0

chmod 755 /etc/letsencrypt/live 2>/dev/null || true
chmod 755 /etc/letsencrypt/live/$DOMAIN 2>/dev/null || true
chmod 755 /etc/letsencrypt/archive 2>/dev/null || true
chmod 755 "$ARCHIVE_DIR" 2>/dev/null || true

chown root:xray "$ARCHIVE_DIR"/privkey*.pem 2>/dev/null || true
chmod 640 "$ARCHIVE_DIR"/privkey*.pem 2>/dev/null || true

chmod 644 "$ARCHIVE_DIR"/fullchain*.pem 2>/dev/null || true
chmod 644 "$ARCHIVE_DIR"/chain*.pem 2>/dev/null || true
chmod 644 "$ARCHIVE_DIR"/cert*.pem 2>/dev/null || true

systemctl restart xray 2>/dev/null || true
systemctl reload nginx 2>/dev/null || true
"""))
    else:
        hook.write_text("#!/bin/bash\nsystemctl reload nginx 2>/dev/null || true")

    hook.chmod(0o755)

    # crontab
    r = _run(["crontab", "-l"], capture=True, check=False)
    existing = r.stdout if r.returncode == 0 else ""
    if "certbot" not in existing:
        new_crontab = existing.rstrip('\n') + "\n0 3 * * * certbot renew --quiet\n"
        _run(["crontab", "-"], input_text=new_crontab, check=False, quiet=True)
    success("Автообновление сертификата настроено")


# =============================================================================
#  ФИЧА 2: МОНИТОРИНГ CERTBOT RENEW + АЛЕРТ
# =============================================================================
def _certbot_renew_and_notify() -> bool:
    """Запускает certbot renew, при ошибке шлёт Telegram."""
    core = _core_module()
    info    = core.info
    warn    = core.warn
    success = core.success
    _run    = core._run
    log_to_file     = core.log_to_file
    _tg_notify_event = core._tg_notify_event
    _log_change      = core._log_change
    STATE_FILE       = core.STATE_FILE
    domain = ""
    try:
        if STATE_FILE.exists():
            domain = json.loads(STATE_FILE.read_text()).get("domain", "")
    except Exception:
        pass

    certbot = next(
        (p for p in (Path("/snap/bin/certbot"), Path("/usr/bin/certbot"))
         if p.exists()), None
    )
    if not certbot:
        warn("certbot не найден")
        return False

    info("Запуск certbot renew...")
    r = _run([str(certbot), "renew", "--quiet", "--non-interactive"],
             check=False, capture=True)
    ok = r.returncode == 0

    if ok:
        # Проверяем сколько дней осталось
        if domain:
            cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
            if cert.exists():
                try:
                    r2 = _run(["openssl", "x509", "-in", str(cert),
                               "-noout", "-enddate"], capture=True, check=False)
                    expiry = r2.stdout.strip().split("=", 1)[1]
                    r3 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
                    days = (int(r3.stdout.strip()) - int(time.time())) // 86400
                    if days > 30:
                        success(f"SSL сертификат действителен: {days} дн.")
                    else:
                        warn(f"SSL истекает через {days} дн.!")
                        _tg_notify_event("cert_expire",
                            f"⚠️ certbot renew OK, но срок истекает через {days} дн.! Домен: {domain}")
                except Exception:
                    pass
        log_to_file("INFO", "certbot renew: success")
        _log_change("certbot_renew", f"SSL сертификат успешно обновлён ({domain})")
    else:
        err = (r.stdout + r.stderr)[:300]
        warn(f"certbot renew завершился с ошибкой:\n{err}")
        log_to_file("ERROR", f"certbot renew failed: {err}")
        _tg_notify_event("cert_expire",
            f"❌ certbot renew <b>FAILED</b>!\nДомен: {domain}\n<code>{err[:200]}</code>")

    return ok


def _certbot_install_monitor_cron() -> None:
    """Cron дважды в день: certbot renew + проверка срока.

    v2 (2026-10-02) — фикс инцидента со спамом в Telegram:
      • send_tg уважает флаг events.cert_expire из telegram.json: если
        администратор выключил событие в меню [5]→[3], алерты замолкают
        немедленно (раньше bash-скрипт слал напрямую через curl, игнорируя
        флаги — источник спама при «выключенных» алертах);
      • анти-спам: «renew FAILED» — максимум 1 алерт в сутки; «истекает
        через N дн.» — 1 алерт в сутки при смене дня; стампы сбрасываются
        при успешном renew / продлении серта;
      • домен читается из state.json при каждом запуске (смена домена в
        меню подхватывается без переустановки cron'а);
      • токен больше не запекается в скрипт — читается из telegram.json
        при каждой отправке (смена токена в меню [5][1] действует сразу).
    """
    core = _core_module()
    success   = core.success
    STATE_FILE = core.STATE_FILE
    domain = ""
    try:
        if STATE_FILE.exists():
            domain = json.loads(STATE_FILE.read_text()).get("domain", "")
    except Exception:
        pass

    sh = _CERTBOT_MONITOR_SCRIPT
    sh.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Certbot renew monitor (Chimera / VLESS Installer)
        # v2 (2026-10-02): уважает events.cert_expire + анти-спам (1 алерт/сутки)
        LOG="/var/log/xray-certbot-monitor.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        TODAY=$(date '+%Y-%m-%d')
        STATE_JSON="/var/lib/xray-installer/state.json"
        STAMP_FAIL="/var/lib/xray-installer/cert-renew-fail.stamp"
        STAMP_EXP="/var/lib/xray-installer/cert-expire-alert.stamp"

        # Домен — из state.json (актуален после смены домена в меню)
        DOMAIN=$(python3 -c "import json; print(json.load(open('$STATE_JSON')).get('domain',''))" 2>/dev/null)
        [ -z "$DOMAIN" ] && DOMAIN="{domain}"

        # certbot: PATH cron'а минимален — ищем в стандартных местах
        CERTBOT=$(command -v certbot 2>/dev/null)
        [ -z "$CERTBOT" ] && [ -x /snap/bin/certbot ] && CERTBOT=/snap/bin/certbot
        [ -z "$CERTBOT" ] && [ -x /usr/bin/certbot ] && CERTBOT=/usr/bin/certbot
        [ -z "$CERTBOT" ] && CERTBOT=certbot

        # Отправка в TG: только если token/chat_id заданы И событие
        # cert_expire включено в telegram.json (меню [5]→[3]).
        send_tg() {{
            python3 -c '
import json, socket, subprocess, sys
from pathlib import Path
msg = sys.argv[1].replace("\\\\n", "\\n")
try:
    cfg = json.loads(Path("/var/lib/xray-installer/telegram.json").read_text())
    token, chat = cfg.get("token"), cfg.get("chat_id")
    if not token or not chat:
        sys.exit(0)
    if not cfg.get("events", {{}}).get("cert_expire", True):
        sys.exit(0)
    host = socket.gethostname().split(".")[0]
    ip = cfg.get("server_ip", "")
    header = "[{{}} | {{}}]".format(host, ip) if ip else "[{{}}]".format(host)
    subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "10",
        "https://api.telegram.org/bot" + token + "/sendMessage",
        "-d", "chat_id=" + chat,
        "-d", "text=" + header + " " + msg,
        "-d", "parse_mode=HTML"], capture_output=True)
except Exception:
    pass
' "$1"
        }}

        log() {{ echo "[$DATE] $1" >> "$LOG"; }}

        log "Running certbot renew..."
        if "$CERTBOT" renew --quiet --non-interactive >> "$LOG" 2>&1; then
            log "certbot renew OK"
            rm -f "$STAMP_FAIL"
            if [ -n "$DOMAIN" ]; then
                CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
                if [ -f "$CERT" ]; then
                    EXPIRY=$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | cut -d= -f2)
                    EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
                    DAYS=$(( (EPOCH - $(date +%s)) / 86400 ))
                    log "SSL days left: $DAYS"
                    if [ "$DAYS" -lt 14 ]; then
                        # Анти-спам: 1 алерт в сутки (метка меняется вместе с днём)
                        TAG="$TODAY:$DAYS"
                        if [ "$(cat "$STAMP_EXP" 2>/dev/null)" != "$TAG" ]; then
                            echo "$TAG" > "$STAMP_EXP"
                            send_tg "⚠️ <b>certbot renew OK</b>, но сертификат истекает через $DAYS дн.!\\nДомен: $DOMAIN"
                        fi
                    else
                        rm -f "$STAMP_EXP"
                    fi
                fi
            fi
        else
            log "certbot renew FAILED"
            # Анти-спам: FAILED-алерт максимум 1 раз в сутки
            if [ "$(cat "$STAMP_FAIL" 2>/dev/null)" != "$TODAY" ]; then
                echo "$TODAY" > "$STAMP_FAIL"
                send_tg "❌ <b>certbot renew FAILED</b>\\nДомен: $DOMAIN\\nЛог: /var/log/letsencrypt/letsencrypt.log"
            fi
        fi
        # Перезагружаем nginx после обновления
        systemctl reload nginx >> "$LOG" 2>&1 || true
    """))
    sh.chmod(0o750)
    # Дважды в день: 03:00 и 15:00
    _CERTBOT_MONITOR_CRON.write_text(
        f"0 3,15 * * * root {sh} >> /var/log/xray-certbot-monitor.log 2>&1\n"
    )
    _CERTBOT_MONITOR_CRON.chmod(0o644)
    success("Certbot monitor cron установлен (03:00 и 15:00 ежедневно)")


def do_manage_certbot_monitor() -> None:
    """Меню управления мониторингом SSL-сертификата."""
    core = _core_module()
    warn    = core.warn
    success = core.success
    _run    = core._run
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    STATE_FILE  = core.STATE_FILE
    BLUE = core.BLUE
    CYAN = core.CYAN
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, NC, GREEN, RED, YELLOW, BLUE = (core.CYAN, core.NC, core.GREEN, core.RED,
                                          core.YELLOW, core.BLUE)
    DIM = core.DIM
    # _certbot_renew_and_notify / _certbot_install_monitor_cron — модуль-локальные
    while True:
        os.system("clear")
        cron_active = _CERTBOT_MONITOR_CRON.exists()
        domain = ""
        days_left = 0
        try:
            if STATE_FILE.exists():
                domain = json.loads(STATE_FILE.read_text()).get("domain", "")
            if domain:
                cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
                if cert.exists():
                    r = _run(["openssl", "x509", "-in", str(cert),
                              "-noout", "-enddate"], capture=True, check=False)
                    expiry = r.stdout.strip().split("=", 1)[1]
                    r2 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
                    days_left = (int(r2.stdout.strip()) - int(time.time())) // 86400
        except Exception:
            pass

        # Статус TG-события cert_expire (меню [5]→[3]; bash-мониторы v2
        # тоже читают этот флаг — выключенное событие глушит ВСЕ cert-алерты)
        tg_cfg = {}
        try:
            _tgf = Path("/var/lib/xray-installer/telegram.json")
            if _tgf.exists():
                tg_cfg = json.loads(_tgf.read_text())
        except Exception:
            tg_cfg = {}
        tg_ready = bool(tg_cfg.get("token") and tg_cfg.get("chat_id"))
        cert_alerts_on = tg_ready and tg_cfg.get("events", {}).get("cert_expire", True)

        print()
        _box_top(f"Мониторинг SSL-сертификата")
        _box_row(f"  Домен:        {CYAN}{domain or '—'}{NC}")
        if days_left:
            col = GREEN if days_left > 30 else YELLOW if days_left > 14 else RED
            _box_row(f"  Срок:         {col}{days_left} дн. до истечения{NC}")
        _box_row(f"  Cron (2×день): {''+GREEN+'ВКЛЮЧЁН'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЁН'+NC}")
        if tg_ready:
            _box_row(f"  TG-алерты:    {GREEN+'ВКЛ (событие cert_expire)'+NC if cert_alerts_on else DIM+'ВЫКЛ — уведомления о серте не придут'+NC}")
        else:
            _box_row(f"  TG-алерты:    {DIM}не настроены (меню [5] Безопасность → Telegram){NC}")
        _box_item("1", f"{'Отключить' if cron_active else 'Включить'} авто-мониторинг (03:00 + 15:00)")
        _box_item("2", f"Запустить certbot renew прямо сейчас")
        if tg_ready:
            _box_item("3", f"{'Выключить' if cert_alerts_on else 'Включить'} TG-алерты по сертификату (cert_expire)")
        _box_item("4", f"Показать лог")
        _box_back()
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if cron_active:
                _CERTBOT_MONITOR_CRON.unlink(missing_ok=True)
                _CERTBOT_MONITOR_SCRIPT.unlink(missing_ok=True)
                success("Certbot monitor отключён")
            else:
                _certbot_install_monitor_cron()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            print()
            _certbot_renew_and_notify()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3" and tg_ready:
            # Toggle cert_expire в telegram.json — bash-мониторы v2 читают
            # этот флаг при каждой отправке, действует немедленно.
            events = tg_cfg.get("events", {})
            events["cert_expire"] = not events.get("cert_expire", True)
            tg_cfg["events"] = events
            try:
                _tgf = Path("/var/lib/xray-installer/telegram.json")
                _tgf.write_text(json.dumps(tg_cfg, indent=2, ensure_ascii=False))
                _tgf.chmod(0o600)
                success(f"TG-алерты по сертификату: {'ВКЛЮЧЕНЫ' if events['cert_expire'] else 'ВЫКЛЮЧЕНЫ'}")
            except Exception as e:
                warn(f"Не удалось записать telegram.json: {e}")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            lp = Path("/var/log/xray-certbot-monitor.log")
            if lp.exists():
                print()
                print('\n'.join(lp.read_text().splitlines()[-30:]))
            else:
                warn("Лог пуст")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
