"""
vless_installer/modules/ru_subnets.py
───────────────────────────────────────────────────────────────────────────────
РФ подсети (RIPE NCC delegated-ripencc-latest) → Xray direct outbound.

Содержит:
  • Интерактивное меню «РФ подсети RIPE NCC → direct» (защита от цензора)
  • Загрузку delegated-ripencc-latest и парсинг IPv4/IPv6 блоков РФ
  • Применение/удаление routing-правил в Xray (outboundTag=direct)
  • Восстановление правил после пересоздания конфига
  • systemd timer для ежедневного авто-обновления (--update-ru-subnets)

Точки входа из _core.py:
    from vless_installer.modules.ru_subnets import (
        RU_SUBNETS_FILE, RU_SUBNETS_TIMER, RU_SUBNETS_SERVICE,
        RIPE_DELEGATED_URL, RIPE_DELEGATED_URL_MIRROR, _RU_SUBNET_RULE_COMMENT,
        _fetch_ru_subnets_from_ripe, _ru_subnets_apply_to_xray,
        _ru_subnets_remove_from_xray, _ru_subnets_install_timer,
        _ru_subnets_remove_timer, _ru_subnets_cli_update,
        do_manage_ru_subnet_direct,
    )

Доступ к helpers ядра (_run, _box_*, цвета, _nginx_restart_if_reality, _set_config_owner, smoke_test_xray, ...) — через importlib (lazy binding), как и в других извлечённых модулях (geoip_block.py, asn_cache.py, warp.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations
import json
import math
import os
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

# ── Константы ─────────────────────────────────────────────────────────────────
RU_SUBNETS_FILE    = Path("/etc/xray/ru_subnets_ripe.txt")
RU_SUBNETS_TIMER   = Path("/etc/systemd/system/xray-ru-subnets.timer")
RU_SUBNETS_SERVICE = Path("/etc/systemd/system/xray-ru-subnets.service")
RIPE_DELEGATED_URL        = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest"
RIPE_DELEGATED_URL_MIRROR = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"
_RU_SUBNET_RULE_COMMENT   = "ru_subnets_ripe"


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("vless_installer._core")



def _fetch_ru_subnets_from_ripe() -> list:
    """
    Скачивает delegated-ripencc-latest и извлекает IPv4/IPv6 блоки РФ.

    При успехе — обновляет SQLite-кэш ('ru_delegated').
    При недоступности RIPE — возвращает данные из кэша (с предупреждением).
    """
    core = _core_module()
    ASN_CACHE_DB             = core.ASN_CACHE_DB
    ASN_CACHE_MAX_AGE_DAYS   = core.ASN_CACHE_MAX_AGE_DAYS
    _asn_cache_load          = core._asn_cache_load
    _asn_cache_save          = core._asn_cache_save
    info                     = core.info
    warn                     = core.warn
    import urllib.request
    import math

    _CACHE_KEY = "ru_delegated"

    def _download(url):
        req = urllib.request.Request(url, headers={"User-Agent": "xray-installer/3.5"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8", errors="replace")

    raw = ""
    for url in (RIPE_DELEGATED_URL, RIPE_DELEGATED_URL_MIRROR):
        try:
            info(f"Загрузка из RIPE NCC: {url}")
            raw = _download(url)
            if raw:
                break
        except Exception as e:
            warn(f"Ошибка загрузки {url}: {e}")

    if not raw:
        # --- Попытка восстановить данные из SQLite-кэша ---
        cached_cidrs, age_days = _asn_cache_load(_CACHE_KEY)
        if cached_cidrs:
            age_str = f"{age_days:.1f}" if age_days is not None else "?"
            if age_days is not None and age_days > ASN_CACHE_MAX_AGE_DAYS:
                warn(
                    f"RIPE NCC недоступен. Используется УСТАРЕВШИЙ кэш "
                    f"(возраст: {age_str} дней, лимит: {ASN_CACHE_MAX_AGE_DAYS}). "
                    f"Данные могут быть неактуальны."
                )
            else:
                warn(
                    f"RIPE NCC недоступен. Используется локальный кэш "
                    f"(возраст: {age_str} дней, {len(cached_cidrs)} префиксов)."
                )
            return cached_cidrs
        warn("RIPE NCC недоступен и локальный кэш пуст — список РФ подсетей не получен.")
        return []

    cidrs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 6:
            continue
        _, cc, typ, start, value = parts[0], parts[1], parts[2], parts[3], parts[4]
        if cc.upper() != "RU":
            continue
        if typ == "ipv4":
            try:
                prefix = 32 - int(math.log2(int(value)))
                cidrs.append(f"{start}/{prefix}")
            except Exception:
                pass
        elif typ == "ipv6":
            try:
                cidrs.append(f"{start}/{int(value)}")
            except Exception:
                pass

    # --- Обновляем кэш при успешной загрузке ---
    if cidrs:
        _asn_cache_save(_CACHE_KEY, cidrs)
        info(f"  [кэш ASN] Обновлён кэш '{_CACHE_KEY}': {len(cidrs)} префиксов → {ASN_CACHE_DB}")

    return cidrs


def _ru_subnets_save(cidrs: list) -> None:
    core = _core_module()
    info                     = core.info
    RU_SUBNETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with RU_SUBNETS_FILE.open("w") as f:
        f.write(f"# РФ подсети из RIPE NCC delegated-ripencc-latest\n")
        f.write(f"# Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Всего блоков: {len(cidrs)}\n")
        for cidr in sorted(cidrs):
            f.write(cidr + "\n")
    info(f"Сохранено {len(cidrs)} подсетей → {RU_SUBNETS_FILE}")


def _ru_subnets_load_from_file() -> list:
    if not RU_SUBNETS_FILE.exists():
        return []
    return [l.strip() for l in RU_SUBNETS_FILE.read_text().splitlines()
            if l.strip() and not l.startswith("#")]


def _ru_subnets_restore_if_needed(silent: bool = False) -> bool:
    """
    Если файл с РФ-подсетями существует — молча восстанавливает правила в конфиге Xray.
    Вызывается после каждого пересоздания конфига (generate_xray_config*,
    _apply_split_tunnel_config_from_state, редактирование ноды и т.д.),
    чтобы правила ru_subnets_ripe не терялись.

    Возвращает True если правила были восстановлены, False если файла нет или он пуст.
    """
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    _RU_SUBNET_RULE_COMMENT  = core._RU_SUBNET_RULE_COMMENT
    _set_config_owner        = core._set_config_owner
    info                     = core.info
    warn                     = core.warn
    AWG_EXIT_ENABLED         = getattr(core, "AWG_EXIT_ENABLED", False)
    cidrs = _ru_subnets_load_from_file()
    if not cidrs:
        return False
    # AWG-режим: РФ-подсети должны идти через "direct-local" (без fwmark → default route ОС),
    # а не через "direct" (с fwmark → awg0 → exit-VPS). Иначе RIPE-маршрутизация
    # бесполезна — 2ip.ru и прочие РФ-сайты увидят IP exit-VPS вместо IP entry.
    _ripe_outbound = "direct-local" if AWG_EXIT_ENABLED else "direct"
    # Применяем без перезапуска Xray — перезапуск сделает вызывающий код
    written: set = set()
    ok = False
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
            cfg     = json.loads(cfg_path.read_text())
            routing = cfg.setdefault("routing", {})
            # Убираем старые RIPE-правила (если есть), вставляем новые в начало
            rules = [r for r in routing.setdefault("rules", [])
                     if r.get("comment") != _RU_SUBNET_RULE_COMMENT]
            new_rules = []
            for i in range(0, len(cidrs), 500):
                new_rules.append({
                    "type":        "field",
                    "ip":          cidrs[i:i + 500],
                    "outboundTag": _ripe_outbound,
                    "comment":     _RU_SUBNET_RULE_COMMENT,
                })
            # BUGFIX: убеждаемся что catch-all существует перед вставкой RIPE-правил.
            # Актуально для конфигов, созданных до патча (нет правила tcp,udp→direct).
            _has_balancer = bool(routing.get("balancers"))
            _has_catchall = any(
                r.get("network") in ("tcp,udp", "tcp", "udp")
                and not r.get("ip") and not r.get("domain")
                and not r.get("protocol") and not r.get("port")
                for r in rules
            )
            if not _has_catchall and not _has_balancer:
                _service_tags = {"direct", "direct-local", "BLOCK", "block", "xray-stats-api"}
                _catchall_tag = "direct"
                outbounds = cfg.get("outbounds", [])
                for _ob in outbounds:
                    _t = _ob.get("tag", "")
                    if _t and _t not in _service_tags:
                        _catchall_tag = _t
                        break
                rules.append({
                    "type":        "field",
                    "network":     "tcp,udp",
                    "outboundTag": _catchall_tag,
                })
                if not silent:
                    info(f"catch-all правило добавлено в конфиг → {_catchall_tag}")
            routing["rules"] = new_rules + rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            ok = True
        except Exception as e:
            if not silent:
                warn(f"Ошибка восстановления RIPE-правил в {cfg_path}: {e}")
    if ok and not silent:
        info(f"РФ подсети RIPE восстановлены в конфиге ({len(cidrs)} CIDR, "
             f"{(len(cidrs) + 499) // 500} правил, outbound={_ripe_outbound})")
    return ok


def _ru_subnets_apply_to_xray(cidrs: list) -> bool:
    core = _core_module()
    AWG_EXIT_ENABLED         = core.AWG_EXIT_ENABLED
    CONFIG_DIR               = core.CONFIG_DIR
    PARAM_SOCKET_PATH        = core.PARAM_SOCKET_PATH
    PROTOCOL_MODE            = core.PROTOCOL_MODE
    XRAY_SERVICE             = core.XRAY_SERVICE
    _RU_SUBNET_RULE_COMMENT  = core._RU_SUBNET_RULE_COMMENT
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run                     = core._run
    _set_config_owner        = core._set_config_owner
    info                     = core.info
    smoke_test_xray          = core.smoke_test_xray
    success                  = core.success
    warn                     = core.warn
    if not cidrs:
        warn("Список подсетей пуст")
        return False
    # AWG-режим: РФ-подсети через "direct-local" (без fwmark), иначе через "direct".
    _ripe_outbound = "direct-local" if AWG_EXIT_ENABLED else "direct"
    written: set = set()
    ok = False
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
            cfg      = json.loads(cfg_path.read_text())
            routing  = cfg.setdefault("routing", {})
            rules    = [r for r in routing.setdefault("rules", [])
                        if r.get("comment") != _RU_SUBNET_RULE_COMMENT]
            outbounds = cfg.setdefault("outbounds", [])
            # В AWG-режиме нужен "direct-local" (без fwmark). Если его нет — добавляем.
            # В классическом режиме — "direct" (как и раньше).
            if AWG_EXIT_ENABLED:
                if not any(ob.get("tag") == "direct-local" for ob in outbounds):
                    outbounds.append({
                        "protocol": "freedom",
                        "tag":      "direct-local",
                        "settings": {"domainStrategy": "UseIPv4"},
                    })
                    info("AWG: добавлен outbound direct-local для RIPE-маршрутизации")
            else:
                if not any(ob.get("tag") == "direct" for ob in outbounds):
                    outbounds.append({"protocol": "freedom", "tag": "direct"})
            new_rules = []
            for i in range(0, len(cidrs), 500):
                new_rules.append({
                    "type":        "field",
                    "ip":          cidrs[i:i + 500],
                    "outboundTag": _ripe_outbound,
                    "comment":     _RU_SUBNET_RULE_COMMENT,
                })
            # BUGFIX: убеждаемся что catch-all существует перед вставкой RIPE-правил.
            # Без него весь не-РФ трафик не имеет маршрута → клиенты получают EOF.
            # Не добавляем если есть балансировщик (Режим B) — там catch-all через balancerTag.
            _has_balancer = bool(routing.get("balancers"))
            _has_catchall = any(
                r.get("network") in ("tcp,udp", "tcp", "udp")
                and not r.get("ip") and not r.get("domain")
                and not r.get("protocol") and not r.get("port")
                for r in rules
            )
            if not _has_catchall and not _has_balancer:
                _service_tags = {"direct", "direct-local", "BLOCK", "block", "xray-stats-api"}
                _catchall_tag = "direct"
                for _ob in outbounds:
                    _t = _ob.get("tag", "")
                    if _t and _t not in _service_tags:
                        _catchall_tag = _t
                        break
                rules.append({
                    "type":        "field",
                    "network":     "tcp,udp",
                    "outboundTag": _catchall_tag,
                })
                info(f"catch-all правило добавлено в конфиг → {_catchall_tag}")
            routing["rules"] = new_rules + rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            info(f"Конфиг: {cfg_path} ({len(new_rules)} правил, {len(cidrs)} CIDR, "
                 f"outbound={_ripe_outbound})")
            ok = True
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")
    if not ok:
        warn("Конфиг Xray не найден")
        return False
    # BUGFIX: на уже установленных системах xray.service может содержать
    # ExecStartPre: rm -f PARAM_SOCKET_PATH — это удаляет unix-сокет которым
    # владеет nginx (nginx bind-ится на него), вызывая EOF у клиентов.
    # Патчим unit на лету перед restart чтобы исправить существующие установки.
    if PROTOCOL_MODE == "reality" and PARAM_SOCKET_PATH and not AWG_EXIT_ENABLED:
        try:
            svc_text = XRAY_SERVICE.read_text()
            if f"rm -f {PARAM_SOCKET_PATH}" in svc_text:
                patched_lines = [l for l in svc_text.splitlines()
                                 if not ("rm -f" in l and PARAM_SOCKET_PATH in l)]
                XRAY_SERVICE.write_text("\n".join(patched_lines) + "\n")
                _run(["systemctl", "daemon-reload"], check=False, quiet=True)
                info("xray.service: убран ExecStartPre rm -f socket (BUGFIX)")
        except Exception:
            pass  # не критично — _nginx_restart_if_reality восстановит сокет
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    # Ждём xray активно (до 15 сек). sleep(2) недостаточно при большом конфиге
    # с тысячами RIPE/AS правил — xray может подниматься дольше.
    # Если xray не active в момент проверки — nginx не перезапустится
    # и останется с proxy_pass к старому сокету → постоянный EOF клиентов.
    # Ждём xray до 90 сек: конфиг с 13 000+ RIPE-правил поднимается 30–60 сек,
    # range(15) было недостаточно и приводило к тому что _nginx_restart_if_reality
    # не вызывалась вовсе. Теперь nginx перезапускается в любом случае.
    for _wi in range(90):
        r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if r.stdout.strip() == "active":
            break
        time.sleep(1)
    if r.stdout.strip() != "active":
        warn("Xray не запустился за 90 сек — проверьте: journalctl -u xray -n 30")
        _nginx_restart_if_reality()   # nginx перезапускаем в любом случае
        return False
    success(f"Xray перезапущен — {len(cidrs)} РФ подсетей → direct")
    _nginx_restart_if_reality()
    smoke_test_xray()
    return True


def _ru_subnets_remove_from_xray() -> None:
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    _RU_SUBNET_RULE_COMMENT  = core._RU_SUBNET_RULE_COMMENT
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run                     = core._run
    _set_config_owner        = core._set_config_owner
    success                  = core.success
    warn                     = core.warn
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
            routing = cfg.get("routing", {})
            routing["rules"] = [r for r in routing.get("rules", [])
                                 if r.get("comment") != _RU_SUBNET_RULE_COMMENT]
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
        except Exception as e:
            warn(f"Ошибка {cfg_path}: {e}")
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    _nginx_restart_if_reality()
    success("Правила РФ подсетей удалены из Xray")


def _ru_subnets_install_timer(hour: int = 4, minute: int = 0) -> None:
    core = _core_module()
    _run                     = core._run
    success                  = core.success
    script_path = Path(sys.argv[0]).resolve()
    RU_SUBNETS_SERVICE.write_text(f"""[Unit]
Description=Обновление РФ подсетей RIPE NCC → Xray direct
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={sys.executable} {script_path} --update-ru-subnets
StandardOutput=journal
StandardError=journal
""")
    RU_SUBNETS_TIMER.write_text(f"""[Unit]
Description=Ежесуточное обновление РФ подсетей RIPE NCC

[Timer]
OnCalendar=*-*-* {hour:02d}:{minute:02d}:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
""")
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "--now", "xray-ru-subnets.timer"], check=False, quiet=True)
    success(f"Timer установлен: обновление каждый день в {hour:02d}:{minute:02d}")


def _ru_subnets_remove_timer() -> None:
    core = _core_module()
    _run                     = core._run
    success                  = core.success
    _run(["systemctl", "disable", "--now", "xray-ru-subnets.timer"], check=False, quiet=True)
    for f in (RU_SUBNETS_TIMER, RU_SUBNETS_SERVICE):
        try:
            f.unlink(missing_ok=True)
        except Exception:
            pass
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    success("Timer xray-ru-subnets удалён")


def _ru_subnets_timer_status() -> str:
    core = _core_module()
    GREEN                    = core.GREEN
    NC                       = core.NC
    RED                      = core.RED
    YELLOW                   = core.YELLOW
    _run                     = core._run
    r = _run(["systemctl", "is-enabled", "xray-ru-subnets.timer"], capture=True, check=False)
    enabled = r.stdout.strip() in ("enabled", "static")
    r2 = _run(["systemctl", "is-active", "xray-ru-subnets.timer"], capture=True, check=False)
    active = r2.stdout.strip() == "active"
    if enabled and active:   return f"{GREEN}активен{NC}"
    elif enabled:            return f"{YELLOW}включён, не запущен{NC}"
    else:                    return f"{RED}отключён{NC}"


def do_manage_ru_subnet_direct() -> None:
    """Меню управления модулем «РФ подсети RIPE → direct»."""
    core = _core_module()
    BLUE                     = core.BLUE
    CYAN                     = core.CYAN
    DIM                      = core.DIM
    GREEN                    = core.GREEN
    NC                       = core.NC
    RED                      = core.RED
    YELLOW                   = core.YELLOW
    _box_bottom              = core._box_bottom
    _box_item                = core._box_item
    _box_row                 = core._box_row
    _box_top                 = core._box_top
    _show_xray_routing_rules = core._show_xray_routing_rules
    _xray_count_ru_subnet_rules = core._xray_count_ru_subnet_rules
    info                     = core.info
    success                  = core.success
    warn                     = core.warn
    while True:
        os.system("clear")
        print()
        _box_top(f"РФ подсети RIPE NCC → direct (защита от цензора)")
        if RU_SUBNETS_FILE.exists():
            _lines = [l for l in RU_SUBNETS_FILE.read_text().splitlines()
                      if l and not l.startswith("#")]
            _mtime = datetime.fromtimestamp(RU_SUBNETS_FILE.stat().st_mtime)
            file_status = (f"{GREEN}{len(_lines)} подсетей{NC}  "
                           f"(обновлён {_mtime.strftime('%Y-%m-%d %H:%M')})")
        else:
            file_status = f"{YELLOW}файл не создан{NC}"
        _ru_active = _xray_count_ru_subnet_rules()
        xray_status = (f"{GREEN}{_ru_active} правил в Xray{NC}"
                       if _ru_active else f"{RED}не применены{NC}")
        timer_st = _ru_subnets_timer_status()
        _box_row(f"  Файл подсетей  : {file_status}")
        _box_row(f"  Правила в Xray : {xray_status}")
        _box_row(f"  Авто-обновление: {timer_st}")
        _box_item("1", f"Скачать/обновить подсети из RIPE NCC и применить в Xray")
        _box_item("2", f"Применить из сохранённого файла (без загрузки)")
        _box_item("3", f"Настроить время авто-обновления (systemd timer)")
        _box_item("4", f"Отключить авто-обновление (удалить timer)")
        _box_item("5", f"{RED}Удалить правила РФ подсетей из Xray{NC}")
        _box_item("6", f"Показать первые 20 подсетей из файла")
        _box_item("7", f"{CYAN}Просмотр всех routing-правил Xray{NC}")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            print()
            info("Начинаем загрузку из RIPE NCC (30-60 сек)...")
            cidrs = _fetch_ru_subnets_from_ripe()
            if not cidrs:
                warn("Не удалось получить подсети — проверьте интернет")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            success(f"Получено {len(cidrs)} подсетей РФ")
            _ru_subnets_save(cidrs)
            _ru_subnets_apply_to_xray(cidrs)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            cidrs = _ru_subnets_load_from_file()
            if not cidrs:
                warn(f"Файл не найден или пуст: {RU_SUBNETS_FILE}")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            _ru_subnets_apply_to_xray(cidrs)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            try:
                h_raw  = input("  Час запуска (0-23) [4]: ").strip()
                m_raw  = input("  Минута (0-59)  [0]: ").strip()
                hour   = int(h_raw) if h_raw else 4
                minute = int(m_raw) if m_raw else 0
                if not (0 <= hour <= 23 and 0 <= minute <= 59):
                    raise ValueError
            except ValueError:
                warn("Неверный формат — используем 04:00")
                hour, minute = 4, 0
            _ru_subnets_install_timer(hour, minute)
            warn("ВАЖНО: timer запускает: " + str(Path(sys.argv[0]).resolve()) + " --update-ru-subnets")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            ans = input(f"  {YELLOW}Отключить авто-обновление? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                _ru_subnets_remove_timer()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            ans = input(f"  {YELLOW}Удалить правила РФ подсетей из Xray? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                _ru_subnets_remove_from_xray()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "6":
            cidrs = _ru_subnets_load_from_file()
            print()
            if cidrs:
                for c in cidrs[:20]:
                    print(f"    {c}")
                if len(cidrs) > 20:
                    print(f"    {DIM}... и ещё {len(cidrs) - 20} подсетей{NC}")
            else:
                warn("Файл пуст или не существует")
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "7":
            _show_xray_routing_rules()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


def _ru_subnets_cli_update() -> None:
    """Вызывается systemd timer: --update-ru-subnets."""
    core = _core_module()
    log_to_file              = core.log_to_file
    log_to_file("INFO", "=== Авто-обновление РФ подсетей RIPE NCC ===")
    cidrs = _fetch_ru_subnets_from_ripe()
    if not cidrs:
        log_to_file("ERROR", "Не удалось получить подсети из RIPE NCC")
        sys.exit(1)
    _ru_subnets_save(cidrs)
    ok = _ru_subnets_apply_to_xray(cidrs)
    log_to_file("INFO", f"Обновление: {len(cidrs)} подсетей, xray={'OK' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
