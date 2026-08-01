"""
chimera/modules/as_direct.py
───────────────────────────────────────────────────────────────────────────────
AS-direct routing — маршрутизация трафика провайдера/хостера по ASN.

Принцип: пользователь вводит номер AS (например AS8359 или 8359).
Скрипт запрашивает все анонсируемые префиксы этого AS через RIPE Stat API
и вставляет их в Xray routing с выбранным действием:
  direct — напрямую, минуя VPN
  proxy  — через VPN (основной outbound)
  block  — заблокировать (blackhole)

Файлы:
  /etc/xray/as_direct_<ASN>.txt — кеш префиксов для каждого AS
  /etc/xray/as_direct_list.json — список активных ASN
    Формат: [{"asn": "AS8359", "action": "direct"}, ...]
Комментарий правила Xray: "as_direct_<ASN>" (например "as_direct_AS8359")
systemd: xray-as-direct.timer / .service (обновляет все активные AS)
CLI-флаг: --update-as-direct

Точки входа из _core.py:
    from chimera.modules.as_direct import (
        AS_DIRECT_DIR, AS_DIRECT_LIST_FILE, AS_DIRECT_TIMER, AS_DIRECT_SERVICE,
        RIPE_STAT_PREFIXES_URL,
        _as_normalize, _resolve_asn_from_input, _as_validate, _as_direct_file,
        _as_direct_list_load, _as_direct_list_save, _fetch_prefixes_for_asn,
        _as_direct_save, _as_direct_apply_to_xray, _as_direct_remove_from_xray,
        _as_suggest_server_asn, _as_direct_install_timer, _as_direct_remove_timer,
        _as_direct_cli_update, _as_ask_action, _as_action_label, do_manage_as_direct,
    )

Доступ к helpers ядра (_run, _box_*, цвета, _nginx_restart_if_reality, _set_config_owner, smoke_test_xray, _asn_cache_*, ...) — через importlib (lazy binding), как и в других извлечённых модулях.
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations
import json
import os
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

# ── Константы ─────────────────────────────────────────────────────────────────
AS_DIRECT_DIR       = Path("/etc/xray")
AS_DIRECT_LIST_FILE = Path("/etc/xray/as_direct_list.json")
AS_DIRECT_TIMER     = Path("/etc/systemd/system/xray-as-direct.timer")
AS_DIRECT_SERVICE   = Path("/etc/systemd/system/xray-as-direct.service")
RIPE_STAT_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}&starttime=last"


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("chimera._core")



def _as_normalize(raw: str) -> str:
    """Приводит ввод к виду 'AS12345'. Принимает '12345', 'as12345', 'AS12345'."""
    raw = raw.strip().upper()
    if raw.startswith("AS"):
        return raw
    if raw.isdigit():
        return f"AS{raw}"
    return raw


def _resolve_asn_from_input(raw: str) -> tuple:
    """
    Определяет ASN по IP-адресу или доменному имени.
    Возвращает (asn, org_label) или ("", "") при ошибке.
    Пример: "8.8.8.8" → ("AS15169", "Google LLC")
             "google.com" → ("AS15169", "Google LLC")
    """
    core = _core_module()
    success                  = core.success
    import re as _re
    import socket as _socket

    target = raw.strip()
    # Если это домен — резолвим в IP через DoH + fallback (минуя локальный кэш).
    # Это нужно, чтобы ASN определялся по АКТУАЛЬНОМУ IP ноды, а не по
    # устаревшей кэш-записи (баг с node-b.example и т.п.).
    if not _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        try:
            from chimera.modules.chain_nodes import _resolve_host_fresh
            ip = _resolve_host_fresh(target)
        except Exception:
            ip = None
        if ip:
            target = ip
        else:
            try:
                target = _socket.gethostbyname(target)
            except Exception:
                return ("", "")
    # Запрашиваем ASN через ip-api.com
    try:
        import urllib.request as _ur
        url = f"http://ip-api.com/json/{target}?fields=as,org,isp,status"
        req = _ur.Request(url, headers={"User-Agent": "xray-installer/3.99"})
        with _ur.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            as_raw = data.get("as", "")          # "AS12345 FullName"
            asn_num = as_raw.split()[0] if as_raw else ""
            org_label = data.get("isp") or data.get("org", "")
            return (asn_num, org_label)
    except Exception:
        pass
    return ("", "")


def _as_validate(asn: str) -> tuple:
    """
    Проверяет корректность ASN.
    Возвращает (True, "") при успехе или (False, "сообщение об ошибке").
    Правила:
      - формат AS<число>
      - номер в диапазоне 1..4294967295 (RFC 4893)
      - AS0 зарезервирован и не используется
      - AS23456 (AS_TRANS) — служебный, предупреждение
    """
    core = _core_module()
    warn                     = core.warn
    asn = asn.strip().upper()
    if not asn.startswith("AS"):
        return False, f"Неверный формат: {asn!r} — ожидается 'AS<число>' или просто число"
    num_str = asn[2:]
    if not num_str.isdigit():
        return False, f"Неверный формат: {asn!r} — после 'AS' должны идти только цифры"
    num = int(num_str)
    if num == 0:
        return False, "AS0 зарезервирован и не может использоваться"
    if num > 4294967295:
        return False, f"Номер AS {num} превышает максимально допустимый (4294967295)"
    if num == 23456:
        # AS_TRANS — технический AS для совместимости 2-байтных/4-байтных AS
        warn(f"  {asn} — это AS_TRANS (служебный). Возможно, вы имели в виду другой AS?")
    return True, ""


def _as_direct_file(asn: str) -> Path:
    """Путь к файлу кеша для данного ASN."""
    return AS_DIRECT_DIR / f"as_direct_{asn}.txt"


def _as_direct_comment(asn: str) -> str:
    return f"as_direct_{asn}"


def _as_direct_list_load() -> list:
    """
    Возвращает список активных ASN из as_direct_list.json.
    Поддерживает два формата:
      - старый: ["AS8359", ...]  -> конвертируется в новый с action="direct"
      - новый:  [{"asn": "AS8359", "action": "direct"}, ...]
    Всегда возвращает список dict с ключами "asn" и "action".
    """
    try:
        if AS_DIRECT_LIST_FILE.exists():
            data = json.loads(AS_DIRECT_LIST_FILE.read_text())
            if not isinstance(data, list):
                return []
            result = []
            for item in data:
                if isinstance(item, str):
                    result.append({"asn": item, "action": "direct"})
                elif isinstance(item, dict) and "asn" in item:
                    result.append({
                        "asn":    item["asn"],
                        "action": item.get("action", "direct"),
                    })
            return result
    except Exception:
        pass
    return []


def _as_direct_list_save(entries: list) -> None:
    """
    Сохраняет список в новом формате: [{"asn": "AS8359", "action": "direct"}, ...]
    entries -- список dict {"asn": ..., "action": ...}
    """
    AS_DIRECT_DIR.mkdir(parents=True, exist_ok=True)
    seen = {}
    for e in entries:
        seen[e["asn"]] = e
    ordered = sorted(seen.values(), key=lambda x: x["asn"])
    AS_DIRECT_LIST_FILE.write_text(json.dumps(ordered, indent=2, ensure_ascii=False))


def _as_direct_list_get_action(asn: str) -> str:
    """Возвращает действие для ASN или 'direct' если не найден."""
    for e in _as_direct_list_load():
        if e["asn"] == asn:
            return e["action"]
    return "direct"


def _fetch_prefixes_for_asn(asn: str) -> list:
    """
    Скачивает все IPv4/IPv6 префиксы для ASN через RIPE Stat API.
    Возвращает список строк CIDR: сначала IPv4, затем IPv6.

    Особенности:
    - Retry × 3 с экспоненциальной задержкой (1 с → 2 с → 4 с)
    - Два URL: с параметром starttime и без (резервный)
    - Валидация каждого префикса через ipaddress.ip_network()
    - Раздельный подсчёт и логирование IPv4/IPv6
    - Проверка на пустой ответ API
    - При недоступности RIPE Stat — возврат данных из SQLite-кэша
    """
    core = _core_module()
    ASN_CACHE_DB             = core.ASN_CACHE_DB
    ASN_CACHE_MAX_AGE_DAYS   = core.ASN_CACHE_MAX_AGE_DAYS
    _asn_cache_load          = core._asn_cache_load
    _asn_cache_save          = core._asn_cache_save
    info                     = core.info
    warn                     = core.warn
    import urllib.request
    import ipaddress

    _CACHE_KEY = f"asn:{asn}"

    # Два варианта URL: с фильтром по времени и без (резервный)
    urls = [
        RIPE_STAT_PREFIXES_URL.format(asn=asn),
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}",
    ]

    raw = ""
    for url in urls:
        info(f"  Запрос к RIPE Stat API: {url}")
        for attempt in range(1, 4):   # до 3 попыток на каждый URL
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "xray-installer/4.12.10",
                    "Accept":     "application/json",
                })
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                if raw:
                    break
            except Exception as e:
                delay = 2 ** (attempt - 1)
                if attempt < 3:
                    warn(f"  Попытка {attempt}/3 не удалась ({asn}): {e} — повтор через {delay} с")
                    time.sleep(delay)
                else:
                    warn(f"  Попытка {attempt}/3 не удалась ({asn}): {e}")
        if raw:
            break

    if not raw:
        warn(f"  Не удалось получить данные для {asn} из всех источников")
        # --- Попытка восстановить данные из SQLite-кэша ---
        cached_cidrs, age_days = _asn_cache_load(_CACHE_KEY)
        if cached_cidrs:
            age_str = f"{age_days:.1f}" if age_days is not None else "?"
            if age_days is not None and age_days > ASN_CACHE_MAX_AGE_DAYS:
                warn(
                    f"  RIPE Stat недоступен. Используется УСТАРЕВШИЙ кэш для {asn} "
                    f"(возраст: {age_str} дней, лимит: {ASN_CACHE_MAX_AGE_DAYS}). "
                    f"Данные могут быть неактуальны."
                )
            else:
                warn(
                    f"  RIPE Stat недоступен. Используется локальный кэш для {asn} "
                    f"(возраст: {age_str} дней, {len(cached_cidrs)} префиксов)."
                )
            return cached_cidrs
        warn(f"  RIPE Stat недоступен и кэш для {asn} пуст — префиксы не получены.")
        return []

    # --- Разбор JSON ---
    try:
        data = json.loads(raw)
    except Exception as e:
        warn(f"  Ошибка разбора JSON ({asn}): {e}")
        return []

    # --- Проверка статуса API ---
    status = data.get("status", "")
    if status not in ("ok", "maintenance"):
        warn(f"  RIPE Stat вернул статус: {status!r} для {asn}")
        if not data.get("data"):
            return []

    # --- Извлечение префиксов ---
    api_data     = data.get("data") or {}
    prefixes_raw = api_data.get("prefixes") or []
    # Резервный ключ на случай нестандартного ответа API
    if not prefixes_raw:
        prefixes_raw = (api_data.get("announced_space") or {}).get("prefixes") or []

    if not prefixes_raw:
        warn(f"  {asn}: API вернул пустой список префиксов")
        return []

    # --- Валидация и разделение IPv4 / IPv6 ---
    cidrs_v4, cidrs_v6 = [], []
    skipped = 0
    for entry in prefixes_raw:
        prefix = (entry.get("prefix") or "").strip()
        if not prefix:
            continue
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                cidrs_v4.append(str(net))   # нормализуем (убираем хост-биты)
            else:
                cidrs_v6.append(str(net))
        except ValueError:
            skipped += 1

    total = len(cidrs_v4) + len(cidrs_v6)
    info(f"  {asn}: {total} префиксов "
         f"(IPv4: {len(cidrs_v4)}, IPv6: {len(cidrs_v6)}"
         + (f", пропущено некорректных: {skipped}" if skipped else "") + ")")

    if total == 0:
        warn(f"  {asn}: после валидации не осталось ни одного корректного префикса")

    # IPv4 первыми (более частый случай), потом IPv6
    result = cidrs_v4 + cidrs_v6

    # --- Обновляем кэш при успешной загрузке ---
    if result:
        _asn_cache_save(_CACHE_KEY, result)
        info(f"  [кэш ASN] Обновлён кэш '{_CACHE_KEY}': {total} префиксов → {ASN_CACHE_DB}")

    return result


def _as_direct_save(asn: str, cidrs: list) -> None:
    """Сохраняет список CIDR в файл кеша."""
    core = _core_module()
    info                     = core.info
    fpath = _as_direct_file(asn)
    fpath.parent.mkdir(parents=True, exist_ok=True)
    with fpath.open("w") as f:
        f.write(f"# Префиксы {asn} из RIPE Stat API\n")
        f.write(f"# Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Всего: {len(cidrs)}\n")
        for c in sorted(cidrs):
            f.write(c + "\n")
    info(f"  Сохранено {len(cidrs)} префиксов → {fpath}")


def _as_direct_load_from_file(asn: str) -> list:
    fpath = _as_direct_file(asn)
    if not fpath.exists():
        return []
    return [l.strip() for l in fpath.read_text().splitlines()
            if l.strip() and not l.startswith("#")]


def _as_get_proxy_outbound_tag(cfg: dict) -> str:
    """
    Определяет тег основного proxy-outbound из конфига Xray.
    Приоритет: chain-exit-1 > chain-exit > vless-out > первый non-direct/non-block outbound.
    """
    outbounds = cfg.get("outbounds", [])
    # Предпочтительные теги в порядке приоритета
    for preferred in ("chain-exit-1", "chain-exit", "vless-out"):
        for ob in outbounds:
            if ob.get("tag") == preferred:
                return preferred
    # Fallback: первый outbound который не является служебным
    service_tags = {"direct", "block", "BLOCK", "xray-stats-api", "freedom"}
    for ob in outbounds:
        tag = ob.get("tag", "")
        proto = ob.get("protocol", "")
        if tag and tag not in service_tags and proto != "freedom" and proto != "blackhole":
            return tag
    return "direct"


def _as_direct_apply_to_xray(asn: str, cidrs: list, action: str = "direct") -> bool:
    """
    Применяет правила маршрутизации для ASN в Xray routing.

    action:
      "direct" -- трафик идёт напрямую (freedom)
      "proxy"  -- трафик идёт через основной VPN-outbound
      "block"  -- трафик блокируется (blackhole)

    Особенности:
    - Перед вставкой удаляет ВСЕ старые правила с тем же comment (идемпотентность)
    - IPv4 и IPv6 разделяются в отдельные батчи правил
    - Батчи по 500 CIDR (ограничение Xray на размер массива "ip")
    - Новые правила вставляются после других as_direct_*/ru_subnets блоков
    """
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    XRAY_BIN                 = core.XRAY_BIN
    _RU_SUBNET_RULE_COMMENT  = core._RU_SUBNET_RULE_COMMENT
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run                     = core._run
    _set_config_owner        = core._set_config_owner
    info                     = core.info
    smoke_test_xray          = core.smoke_test_xray
    success                  = core.success
    warn                     = core.warn
    AWG_EXIT_ENABLED         = getattr(core, "AWG_EXIT_ENABLED", False)
    import ipaddress

    action = action.lower()
    if action not in ("direct", "proxy", "block"):
        warn(f"  Неизвестное действие '{action}' — используется 'direct'")
        action = "direct"

    if not cidrs:
        warn(f"  Список префиксов для {asn} пуст")
        return False

    cidrs_v4, cidrs_v6 = [], []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                cidrs_v4.append(c)
            else:
                cidrs_v6.append(c)
        except ValueError:
            pass

    comment = _as_direct_comment(asn)
    # AWG-режим: action="direct" должен идти через "direct-local" (без fwmark → default route ОС),
    # иначе РФ/AS-префиксы уйдут через awg0 (exit-VPS) и AS-direct бесполезен.
    _as_direct_outbound = "direct-local" if (AWG_EXIT_ENABLED and action == "direct") else None
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
            outbounds = cfg.setdefault("outbounds", [])

            # Шаг 1: удаляем старые правила этого ASN (идемпотентность)
            rules = [r for r in routing.setdefault("rules", [])
                     if r.get("comment") != comment]

            # Шаг 2: убеждаемся что нужный outbound существует
            if action == "direct":
                if AWG_EXIT_ENABLED:
                    # AWG: "direct-local" (без fwmark → default route ОС)
                    outbound_tag = "direct-local"
                    if not any(ob.get("tag") == "direct-local" for ob in outbounds):
                        outbounds.append({
                            "protocol": "freedom",
                            "tag":      "direct-local",
                            "settings": {"domainStrategy": "UseIPv4"},
                        })
                        info("AWG: добавлен outbound direct-local для AS-direct")
                else:
                    outbound_tag = "direct"
                    if not any(ob.get("tag") == "direct" for ob in outbounds):
                        outbounds.append({"protocol": "freedom", "tag": "direct"})

            elif action == "proxy":
                outbound_tag = _as_get_proxy_outbound_tag(cfg)
                info(f"  Используем proxy outbound: {outbound_tag}")

            else:  # block
                outbound_tag = "block"
                if not any(ob.get("tag") == "block" for ob in outbounds):
                    outbounds.append({"protocol": "blackhole", "tag": "block"})

            # Шаг 3: формируем батчи по 500 CIDR, раздельно для IPv4 и IPv6
            new_rules = []
            for chunk_list in (cidrs_v4, cidrs_v6):
                for i in range(0, len(chunk_list), 500):
                    new_rules.append({
                        "type":        "field",
                        "ip":          chunk_list[i:i + 500],
                        "outboundTag": outbound_tag,
                        "comment":     comment,
                    })

            # Шаг 4: вставляем после блоков ru_subnets/as_direct, перед остальными
            _priority_comments = {_as_direct_comment(e["asn"]) for e in _as_direct_list_load()}
            _priority_comments.add(_RU_SUBNET_RULE_COMMENT)
            insert_pos = 0
            for idx, r in enumerate(rules):
                if r.get("comment", "") in _priority_comments:
                    insert_pos = idx + 1
            rules = rules[:insert_pos] + new_rules + rules[insert_pos:]
            routing["rules"] = rules

            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            action_label = {"direct": "direct (напрямую)", "proxy": f"proxy ({outbound_tag})", "block": "block (заблокирован)"}[action]
            info(f"  Конфиг обновлён: {cfg_path} "
                 f"({len(new_rules)} правил: {len(cidrs_v4)} IPv4 + {len(cidrs_v6)} IPv6 -> {action_label})")
            ok = True
        except Exception as e:
            warn(f"  Ошибка патча {cfg_path}: {e}")

    if not ok:
        warn("  Конфиг Xray не найден")
        return False

    # ── Dry-run проверка конфига перед рестартом (патч: задача #9) ──────────
    _test_cfg = CONFIG_DIR / "config.json"
    if not _test_cfg.exists():
        _test_cfg = Path("/usr/local/etc/xray/config.json")
    if _test_cfg.exists():
        _dry = _run([str(XRAY_BIN), "run", "-test", "-config", str(_test_cfg)],
                    capture=True, check=False, quiet=True)
        if _dry.returncode != 0:
            warn("  Конфиг Xray не прошёл проверку — рестарт отменён")
            warn((_dry.stdout + _dry.stderr)[:300])
            return False

    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    # Ждём xray до 90 сек (тот же RIPE-конфиг, те же 30–60 сек на валидацию)
    for _wi in range(90):
        r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if r.stdout.strip() == "active":
            break
        time.sleep(1)
    if r.stdout.strip() == "active":
        action_label = {"direct": "direct", "proxy": "proxy (VPN)", "block": "BLOCK"}[action]
        success(f"Xray перезапущен -- {asn}: {len(cidrs_v4)} IPv4 + {len(cidrs_v6)} IPv6 -> {action_label}")
        _nginx_restart_if_reality()
        smoke_test_xray()
        return True
    else:
        warn("  Xray не запустился за 90 сек — проверьте: journalctl -u xray -n 30")
        _nginx_restart_if_reality()   # nginx перезапускаем в любом случае
        return False


def _as_direct_remove_from_xray(asn: str) -> None:
    """Удаляет правила для ASN из Xray routing."""
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run                     = core._run
    _set_config_owner        = core._set_config_owner
    success                  = core.success
    warn                     = core.warn
    comment = _as_direct_comment(asn)
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
                                 if r.get("comment") != comment]
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
        except Exception as e:
            warn(f"  Ошибка {cfg_path}: {e}")
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    _nginx_restart_if_reality()
    success(f"Правила {asn} удалены из Xray")


def _as_direct_restore_if_needed(silent: bool = False) -> bool:
    """
    Восстанавливает правила для всех активных AS после пересоздания конфига Xray.
    Вызывается из rebuild_and_restart_xray() и migration.
    Аналог _ru_subnets_restore_if_needed для AS-модуля.
    Поддерживает все три режима: direct / proxy / block.
    """
    core = _core_module()
    info                     = core.info
    warn                     = core.warn
    entries = _as_direct_list_load()
    if not entries:
        return False
    restored = 0
    for entry in entries:
        asn    = entry["asn"]
        action = entry.get("action", "direct")
        cidrs  = _as_direct_load_from_file(asn)
        if not cidrs:
            if not silent:
                warn(f"AS-routing: файл для {asn} не найден, пропуск")
            continue
        ok = _as_direct_apply_to_xray(asn, cidrs, action)
        if ok:
            restored += 1
        elif not silent:
            warn(f"AS-routing восстановление {asn} ({action}): не удалось применить")
    if restored and not silent:
        info(f"AS-routing правила восстановлены ({len(entries)} AS)")
    return restored > 0


def _as_suggest_server_asn() -> None:
    """
    Определяет ASN хостера по IP сервера и предлагает добавить его в direct.
    Задача #3: авто-определение ASN сервера при установке.
    Не вызывается повторно если этот ASN уже в списке или был пропущен.
    """
    core = _core_module()
    BOLD                     = core.BOLD
    DIM                      = core.DIM
    GREEN                    = core.GREEN
    NC                       = core.NC
    _box_bottom              = core._box_bottom
    _box_row                 = core._box_row
    _box_top                 = core._box_top
    _log_change              = core._log_change
    get_server_ip            = core.get_server_ip
    info                     = core.info
    success                  = core.success
    warn                     = core.warn
    # Флаг — не предлагать повторно в рамках сессии
    if getattr(_as_suggest_server_asn, "_done", False):
        return
    _as_suggest_server_asn._done = True  # type: ignore

    server_ip = get_server_ip("4")
    if not server_ip:
        return
    try:
        info(f"Определяю ASN хостера для {server_ip}...")
        asn, org = _resolve_asn_from_input(server_ip)
        if not asn:
            return
        # Уже добавлен?
        cur_map = {e["asn"]: e for e in _as_direct_list_load()}
        if asn in cur_map:
            return
        print()
        _box_top(f"Совет: трафик внутри хостера")
        _box_row(f"  IP сервера {server_ip} принадлежит:")
        _box_row(f"  {BOLD}{asn}{NC}  {DIM}{org}{NC}")
        _box_row(f"  Рекомендуется добавить этот AS в {GREEN}direct{NC},")
        _box_row(f"  чтобы трафик внутри сети хостера не шёл через VPN.")
        _box_bottom()
        ans = input(f"  Добавить {BOLD}{asn}{NC} в direct? [y/N]: ").strip().lower()
        if ans != "y":
            return
        info(f"Загрузка префиксов для {asn}...")
        cidrs = _fetch_prefixes_for_asn(asn)
        if not cidrs:
            warn(f"Не удалось получить префиксы для {asn}")
            return
        _as_direct_save(asn, cidrs)
        ok = _as_direct_apply_to_xray(asn, cidrs, "direct")
        if ok:
            entries = _as_direct_list_load()
            entries.append({"asn": asn, "action": "direct"})
            _as_direct_list_save(entries)
            _log_change("as_routing", f"{asn} добавлен → direct (авто: хостер сервера)")
            success(f"{asn} добавлен → direct")
    except Exception:
        pass


def _as_direct_count_rules(asn: str) -> int:
    """Считает количество правил для ASN в конфиге Xray."""
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    comment = _as_direct_comment(asn)
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            cfg   = json.loads(cfg_path.read_text())
            rules = cfg.get("routing", {}).get("rules", [])
            return sum(1 for r in rules if r.get("comment") == comment)
        except Exception:
            pass
    return 0


def _as_direct_install_timer(hour: int = 5, minute: int = 0) -> None:
    core = _core_module()
    _run                     = core._run
    success                  = core.success
    script_path = Path(sys.argv[0]).resolve()
    AS_DIRECT_SERVICE.write_text(f"""[Unit]
Description=Обновление AS-префиксов (as_direct) → Xray direct
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={sys.executable} {script_path} --update-as-direct
StandardOutput=journal
StandardError=journal
""")
    AS_DIRECT_TIMER.write_text(f"""[Unit]
Description=Ежесуточное обновление AS-префиксов для direct-маршрутизации

[Timer]
OnCalendar=*-*-* {hour:02d}:{minute:02d}:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
""")
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "--now", "xray-as-direct.timer"], check=False, quiet=True)
    success(f"Timer установлен: обновление каждый день в {hour:02d}:{minute:02d}")


def _as_direct_remove_timer() -> None:
    core = _core_module()
    _run                     = core._run
    success                  = core.success
    _run(["systemctl", "disable", "--now", "xray-as-direct.timer"], check=False, quiet=True)
    for f in (AS_DIRECT_TIMER, AS_DIRECT_SERVICE):
        try:
            f.unlink(missing_ok=True)
        except Exception:
            pass
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    success("Timer xray-as-direct удалён")


def _as_direct_timer_status() -> str:
    core = _core_module()
    GREEN                    = core.GREEN
    NC                       = core.NC
    RED                      = core.RED
    YELLOW                   = core.YELLOW
    _run                     = core._run
    r = _run(["systemctl", "is-enabled", "xray-as-direct.timer"], capture=True, check=False)
    enabled = r.stdout.strip() in ("enabled", "static")
    r2 = _run(["systemctl", "is-active", "xray-as-direct.timer"], capture=True, check=False)
    active = r2.stdout.strip() == "active"
    if enabled and active:   return f"{GREEN}активен{NC}"
    elif enabled:            return f"{YELLOW}включён, не запущен{NC}"
    else:                    return f"{RED}отключён{NC}"


def _as_direct_cli_update() -> None:
    """Вызывается systemd timer: --update-as-direct. Обновляет все активные AS."""
    core = _core_module()
    log_to_file              = core.log_to_file
    log_to_file("INFO", "=== Авто-обновление AS-routing префиксов ===")
    entries = _as_direct_list_load()
    if not entries:
        log_to_file("INFO", "AS-routing: список AS пуст — нечего обновлять")
        sys.exit(0)
    errors = 0
    for entry in entries:
        asn    = entry["asn"]
        action = entry.get("action", "direct")
        cidrs  = _fetch_prefixes_for_asn(asn)
        if not cidrs:
            log_to_file("ERROR", f"AS-routing: не удалось получить префиксы для {asn}")
            errors += 1
            continue
        _as_direct_save(asn, cidrs)
        ok = _as_direct_apply_to_xray(asn, cidrs, action)
        log_to_file("INFO", f"AS-routing {asn} ({action}): {len(cidrs)} префиксов, xray={'OK' if ok else 'FAIL'}")
        if not ok:
            errors += 1
    sys.exit(1 if errors else 0)


def _as_ask_action(asn: str = "") -> str:
    """
    Интерактивно спрашивает у пользователя, куда направлять трафик AS.
    Возвращает строку: "direct" | "proxy" | "block" | "" (отмена).
    """
    core = _core_module()
    BOLD                     = core.BOLD
    CYAN                     = core.CYAN
    DIM                      = core.DIM
    GREEN                    = core.GREEN
    NC                       = core.NC
    RED                      = core.RED
    YELLOW                   = core.YELLOW
    import re as _re
    _BW = 46  # внутренняя видимая ширина бокса

    def _row(raw_text: str) -> str:
        visible = _re.sub(r'\033\[[0-9;]*m', '', raw_text)
        pad = _BW - len(visible)
        return f"  {CYAN}║{NC}  {raw_text}{' ' * max(pad, 0)}  {CYAN}║{NC}"

    _title = f"Куда направлять трафик{(' ' + asn) if asn else ' этого AS'}?"
    _title_pad = _BW - len(_title)
    print()
    print(f"  {CYAN}╔{'═' * (_BW + 4)}╗{NC}")
    print(f"  {CYAN}║{NC}  {BOLD}{_title}{NC}{' ' * max(_title_pad, 0)}  {CYAN}║{NC}")
    print(f"  {CYAN}╠{'═' * (_BW + 4)}║{NC}")
    print(_row(f"{GREEN}[1] direct{NC}  — напрямую, минуя VPN"))
    print(_row(f"{YELLOW}[2] proxy{NC}   — через VPN-туннель    "))
    print(_row(f"{RED}[3] block{NC}   — заблокировать        "))
    print(_row(f"{DIM}[Q] Отмена{NC}                          "))
    print(f"  {CYAN}╚{'═' * (_BW + 4)}╝{NC}")
    print()
    ch = input(f"  {CYAN}Выбор [1/2/3/Q]:{NC} ").strip().lower()
    if ch == "1":   return "direct"
    if ch == "2":   return "proxy"
    if ch == "3":   return "block"
    return ""


def _as_action_label(action: str) -> str:
    """Возвращает цветную метку для действия."""
    core = _core_module()
    DIM                      = core.DIM
    GREEN                    = core.GREEN
    NC                       = core.NC
    RED                      = core.RED
    YELLOW                   = core.YELLOW
    return {
        "direct": f"{GREEN}direct{NC}",
        "proxy":  f"{YELLOW}proxy{NC}",
        "block":  f"{RED}block{NC}",
    }.get(action, f"{DIM}{action}{NC}")


def do_manage_as_direct() -> None:
    """Меню управления уже добавленными AS-маршрутами (изменить действие / удалить / обновить)."""
    core = _core_module()
    ASN_CACHE_DB             = core.ASN_CACHE_DB
    ASN_CACHE_MAX_AGE_DAYS   = core.ASN_CACHE_MAX_AGE_DAYS
    BLUE                     = core.BLUE
    BOLD                     = core.BOLD
    CYAN                     = core.CYAN
    DIM                      = core.DIM
    GREEN                    = core.GREEN
    NC                       = core.NC
    CYAN = core.CYAN
    NC = core.NC
    RED                      = core.RED
    YELLOW                   = core.YELLOW
    _asn_cache_info          = core._asn_cache_info
    _box_bottom              = core._box_bottom
    _box_item                = core._box_item
    _box_row                 = core._box_row
    _box_sep                 = core._box_sep
    _box_top                 = core._box_top
    _log_change              = core._log_change
    _show_xray_routing_rules = core._show_xray_routing_rules
    info                     = core.info
    success                  = core.success
    warn                     = core.warn
    while True:
        os.system("clear")
        print()
        entries = _as_direct_list_load()

        _box_top("Управление AS-маршрутами")
        _box_row(f"  {DIM}Здесь можно изменить действие, удалить или обновить{NC}")
        _box_row(f"  {DIM}префиксы для ранее добавленных AS.{NC}")
        _box_row(f"  {DIM}Для добавления нового AS — вернитесь в GeoIP → [6].{NC}")
        _box_sep()

        if entries:
            _box_row(f"  {CYAN}Активные AS ({len(entries)}):{NC}")
            for entry in entries:
                asn    = entry["asn"]
                action = entry.get("action", "direct")
                fpath  = _as_direct_file(asn)
                n_file = 0
                mtime  = ""
                if fpath.exists():
                    lines  = [l for l in fpath.read_text().splitlines()
                               if l.strip() and not l.startswith("#")]
                    n_file = len(lines)
                    mtime  = datetime.fromtimestamp(fpath.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                n_xray  = _as_direct_count_rules(asn)
                file_st = (f"{GREEN}{n_file} префиксов{NC} ({mtime})"
                           if n_file else f"{YELLOW}нет кеша{NC}")
                xray_st = (f"{GREEN}{n_xray} правил{NC}" if n_xray else f"{RED}не применён{NC}")
                act_st  = _as_action_label(action)
                _box_row(f"    {BOLD}{asn}{NC}  [{act_st}]  |  {file_st}  |  Xray: {xray_st}")
        else:
            _box_row(f"  {YELLOW}Нет активных AS{NC}")

        _box_sep()
        timer_st = _as_direct_timer_status()
        _box_row(f"  Авто-обновление: {timer_st}")
        _box_sep()

        _box_item("1", f"Изменить действие для AS (direct / proxy / block)")
        _box_item("2", f"Обновить префиксы всех AS (из кеша, без загрузки)")
        _box_item("3", f"Обновить префиксы всех AS (свежая загрузка из RIPE)")
        _box_item("4", f"Удалить AS (убрать из списка + из Xray routing)")
        _box_item("5", f"Настроить время авто-обновления (systemd timer)")
        _box_item("6", f"Отключить авто-обновление (удалить timer)")
        _box_item("7", f"Показать префиксы AS (первые 20)")
        _box_item("8", f"{CYAN}Просмотр всех routing-правил Xray{NC}")
        _box_item("9", f"Показать устаревшие AS (кеш старше 30 дней)")
        _box_item("C", f"🗄️  Состояние SQLite-кэша префиксов ASN")
        _box_item("Q", f"Назад")
        _box_bottom()

        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        # ── [1] Изменить действие ────────────────────────────────────────────
        if ch == "1":
            if not entries:
                warn("Нет активных AS")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            print()
            _box_row("  Активные AS:")
            for i, e in enumerate(entries, 1):
                _box_row(f"    {i}. {BOLD}{e['asn']}{NC}  [{_as_action_label(e['action'])}]")
            _box_bottom()
            raw = input(f"  Введите ASN для смены действия: ").strip()
            if not raw:
                continue
            asn = _as_normalize(raw)
            entry_match = next((e for e in entries if e["asn"] == asn), None)
            if not entry_match:
                warn(f"{asn} не найден в активном списке")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            info(f"Текущее действие для {asn}: {_as_action_label(entry_match['action'])}")
            action = _as_ask_action(asn)
            if not action:
                info("Отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            if action == entry_match["action"]:
                info(f"Действие не изменилось ({action})")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            cidrs = _as_direct_load_from_file(asn)
            if not cidrs:
                info(f"Кеш для {asn} не найден — загружаем из RIPE...")
                cidrs = _fetch_prefixes_for_asn(asn)
                if not cidrs:
                    warn(f"Не удалось получить префиксы для {asn}")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                _as_direct_save(asn, cidrs)
            ok = _as_direct_apply_to_xray(asn, cidrs, action)
            if ok:
                old_action = entry_match["action"]
                entry_match["action"] = action
                _as_direct_list_save(entries)
                _log_change("as_routing", f"{asn}: {old_action} → {action}")
                success(f"{asn}: действие изменено на {_as_action_label(action)}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [2] Обновить из кеша ─────────────────────────────────────────────
        elif ch == "2":
            if not entries:
                warn("Нет активных AS")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            for entry in entries:
                asn    = entry["asn"]
                action = entry.get("action", "direct")
                cidrs  = _as_direct_load_from_file(asn)
                if not cidrs:
                    warn(f"  Кеш для {asn} пуст — пропуск (используйте опцию 3)")
                    continue
                _as_direct_apply_to_xray(asn, cidrs, action)
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [3] Обновить из RIPE ─────────────────────────────────────────────
        elif ch == "3":
            if not entries:
                warn("Нет активных AS")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            for entry in entries:
                asn    = entry["asn"]
                action = entry.get("action", "direct")
                info(f"Обновление {asn} ({_as_action_label(action)})...")
                cidrs = _fetch_prefixes_for_asn(asn)
                if not cidrs:
                    warn(f"  Не удалось получить префиксы для {asn}")
                    continue
                _as_direct_save(asn, cidrs)
                _as_direct_apply_to_xray(asn, cidrs, action)
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [4] Удалить AS ───────────────────────────────────────────────────
        elif ch == "4":
            if not entries:
                warn("Нет активных AS")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            print()
            _box_row("  Активные AS:")
            for i, e in enumerate(entries, 1):
                _box_row(f"    {i}. {BOLD}{e['asn']}{NC}  [{_as_action_label(e['action'])}]")
            _box_bottom()
            raw = input(f"  Введите ASN для удаления: ").strip()
            if not raw:
                continue
            asn = _as_normalize(raw)
            _asn_ok, _asn_err = _as_validate(asn)
            if not _asn_ok:
                warn(f"Неверный ASN {raw!r}: {_asn_err}")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            if not any(e["asn"] == asn for e in entries):
                warn(f"{asn} не найден в активном списке")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            ans = input(f"  {YELLOW}Удалить {asn} из Xray и активного списка? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                _as_direct_remove_from_xray(asn)
                entries = [e for e in entries if e["asn"] != asn]
                _as_direct_list_save(entries)
                _log_change("as_routing", f"{asn} удалён")
                try:
                    _as_direct_file(asn).unlink(missing_ok=True)
                except Exception:
                    pass
                success(f"{asn} удалён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [5] Настроить timer ──────────────────────────────────────────────
        elif ch == "5":
            print()
            try:
                h_raw  = input("  Час запуска (0-23) [5]: ").strip()
                m_raw  = input("  Минута (0-59)  [0]: ").strip()
                hour   = int(h_raw) if h_raw else 5
                minute = int(m_raw) if m_raw else 0
                if not (0 <= hour <= 23 and 0 <= minute <= 59):
                    raise ValueError
            except ValueError:
                warn("Неверный формат — используем 05:00")
                hour, minute = 5, 0
            _as_direct_install_timer(hour, minute)
            warn("ВАЖНО: timer запускает: " + str(Path(sys.argv[0]).resolve()) + " --update-as-direct")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [6] Удалить timer ────────────────────────────────────────────────
        elif ch == "6":
            ans = input(f"  {YELLOW}Отключить авто-обновление AS-routing? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                _as_direct_remove_timer()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [7] Показать префиксы ────────────────────────────────────────────
        elif ch == "7":
            if not entries:
                warn("Нет активных AS")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            print()
            default_asn = entries[0]["asn"]
            raw = input(f"  ASN для просмотра [{default_asn}]: ").strip()
            asn = _as_normalize(raw) if raw else default_asn
            cidrs = _as_direct_load_from_file(asn)
            print()
            if cidrs:
                action = _as_direct_list_get_action(asn)
                print(f"  {CYAN}{asn}{NC} [{_as_action_label(action)}]: {len(cidrs)} префиксов")
                for c in cidrs[:20]:
                    print(f"    {c}")
                if len(cidrs) > 20:
                    print(f"    {DIM}... и ещё {len(cidrs) - 20} префиксов{NC}")
            else:
                warn(f"Кеш для {asn} пуст или не существует")
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [8] Просмотр routing-правил ──────────────────────────────────────
        elif ch == "8":
            _show_xray_routing_rules()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [9] Устаревшие AS (патч: задача #7) ──────────────────────────────
        elif ch == "9":
            if not entries:
                warn("Нет активных AS")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            _stale_days = 30
            _now = time.time()
            print()
            _box_top(f"Устаревшие AS (кеш старше {_stale_days} дней)")
            _found_stale = False
            for entry in entries:
                asn   = entry["asn"]
                fpath = _as_direct_file(asn)
                if not fpath.exists():
                    _box_row(f"  {RED}{asn}{NC}  — {RED}нет файла кеша{NC}")
                    _found_stale = True
                else:
                    age_days = (_now - fpath.stat().st_mtime) / 86400
                    if age_days >= _stale_days:
                        _box_row(f"  {YELLOW}{asn}{NC}  — кеш {YELLOW}{age_days:.0f} дн.{NC} назад")
                        _found_stale = True
            if not _found_stale:
                _box_row(f"  {GREEN}Все AS актуальны (кеш свежее {_stale_days} дней){NC}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [C] Состояние SQLite-кэша ────────────────────────────────────────
        elif ch == "c":
            print()
            _box_top("🗄️  SQLite-кэш префиксов ASN")
            records = _asn_cache_info()
            if not records:
                _box_row(f"  {YELLOW}Кэш пуст — данных нет{NC}")
                _box_row(f"  {DIM}Кэш заполняется автоматически при загрузке из RIPE.{NC}")
            else:
                # Размер файла БД
                try:
                    db_size_kb = ASN_CACHE_DB.stat().st_size // 1024
                    db_size_str = f"{db_size_kb} КБ"
                except Exception:
                    db_size_str = "?"
                _box_row(f"  БД: {CYAN}{ASN_CACHE_DB}{NC}  ({db_size_str})")
                _box_sep()
                _box_row(f"  {'Ключ':<22} {'Префиксов':>10}  {'Обновлён':<17}  {'Возраст':>10}")
                _box_row(f"  {'─'*22} {'─'*10}  {'─'*17}  {'─'*10}")
                for rec in records:
                    age = rec["age_days"]
                    age_str = f"{age:.1f} дн."
                    if age > ASN_CACHE_MAX_AGE_DAYS:
                        age_col = f"{YELLOW}{age_str}{NC}"
                        key_col = f"{YELLOW}{rec['key']:<22}{NC}"
                    else:
                        age_col = f"{GREEN}{age_str}{NC}"
                        key_col = f"{rec['key']:<22}"
                    _box_row(f"  {key_col} {rec['count']:>10}  {rec['updated_str']:<17}  {age_col}")
                _box_sep()
                _box_row(f"  {DIM}Жёлтым выделены записи старше {ASN_CACHE_MAX_AGE_DAYS} дней.{NC}")
                _box_row(f"  {DIM}Сброс отдельной записи: python3 {sys.argv[0]} --clear-asn-cache <ASN|all>{NC}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
