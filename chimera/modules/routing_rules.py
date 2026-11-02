"""
chimera/modules/routing_rules.py
───────────────────────────────────────────────────────────────────────────────
Кастомные routing-правила Xray — полный контроль над routing.rules.

Правило = {
  имя, матч (домены / IP+CIDR / порты), действие (outboundTag),
  вкл/выкл, приоритет, расположение в конфиге }.

Возможности:
  • Матч: домен-паттерны (plain / domain: / full: / regexp: / geosite:),
    IP/CIDR (в т.ч. geoip:), порты/диапазоны. Несколько полей в одном
    правиле = AND (семантика Xray), значения внутри списка = OR.
  • Действие: любой outboundTag из живого конфига (chain-exit-N, direct,
    direct-local, block, ...) или произвольный тег вручную.
  • Приоритет: int, меньше = выше в списке (раньше матчится).
  • Расположение: top (в начало, выше dns_custom/ru_subnets/youtube —
    перебивает встроенные пресеты) | before_catchall (перед catch-all
    в конце — после встроенных).
  • Большие IP-списки автоматически режутся по chunk=500 на правило
    (канон ru_subnets_ripe).
  • Имппорт РФ-подсетей RIPE NCC как правила с любым outbound
    (запрос Vasily: «правила из Split Tunneling, но вместо direct —
    другой outbound»).
  • Re-apply после regenerate (restore_routing_rules_if_needed) —
    вызывается из _core._rebuild_and_restart_xray, ПОСЛЕДНИМ из
    «в начало»-вставляющих: кастомные правила всегда выше встроенных.

State:      /var/lib/xray-installer/routing_rules.json (0600)
Применение: патч routing.rules в /etc/xray/config.json (+ альтернативный
            /usr/local/etc/xray/config.json), comment="custom:<name>".

ОГРАНИЧЕНИЕ (честно): правила действуют на ВСЕХ клиентов сервера сразу —
Xray routing не разделяет трафик по пользователям.

Точки входа из _core.py:
    from chimera.modules.routing_rules import (
        do_manage_routing_rules, restore_routing_rules_if_needed,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from chimera.modules.tui import tui_form, tui_select, tui_confirm, TuiField
from chimera.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
    _box_desc, _box_kv, _box_info, _box_warn, _box_ok, _box_ask,
)

# ── Цвета (канон dns_rules) ───────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
            DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE',
                            'BOLD', 'DIM', 'WHITE', 'NC')}

_C   = _detect_colors()
RED, GREEN, YELLOW = _C['RED'], _C['GREEN'], _C['YELLOW']
CYAN, BLUE, BOLD   = _C['CYAN'], _C['BLUE'], _C['BOLD']
DIM, WHITE, NC     = _C['DIM'], _C['WHITE'], _C['NC']

# ── Логирование (канон dns_rules: /var/log/chimera.log) ───────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] [routing_rules] {clean}\n")
    except Exception:
        pass

def _success(msg: str) -> None:
    print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)

def _warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)

def _info(msg: str) -> None:
    print(f"{CYAN}[..]{NC}    {msg}"); _log("INFO", msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _set_config_owner(path) -> None:
    try:
        import pwd, shutil
        shutil.chown(str(path), user="root", group="root")
    except Exception:
        pass

# ── Константы ─────────────────────────────────────────────────────────────────
RR_STATE_FILE     = Path("/var/lib/xray-installer/routing_rules.json")
RR_COMMENT_PREFIX = "custom:"
RR_DEFAULT_CHUNK  = 500       # канон ru_subnets_ripe: ≤500 CIDR на правило
RR_PLACEMENTS     = ("top", "before_catchall")
RR_NAME_RE        = re.compile(r'^[a-z0-9][a-z0-9._-]{1,63}$')
RR_DOMAIN_PREFIXES = ("domain:", "full:", "regexp:", "geosite:")

_CONFIG_DIR      = Path("/etc/xray")
_ALT_CONFIG      = Path("/usr/local/etc/xray/config.json")


# ══════════════════════════════════════════════════════════════════════════════
#  STATE I/O
# ══════════════════════════════════════════════════════════════════════════════

def _rr_load() -> dict:
    try:
        if RR_STATE_FILE.exists():
            data = json.loads(RR_STATE_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {"version": 1, "rules": []}


def _rr_save(data: dict) -> None:
    RR_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data.setdefault("version", 1)
    RR_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    RR_STATE_FILE.chmod(0o600)


def _rr_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _rr_enabled_rules(state: "dict | None" = None) -> list:
    """Включённые правила, отсортированные по (priority, name) —
    меньше priority = выше в конфиге = раньше матчится."""
    if state is None:
        state = _rr_load()
    rules = [r for r in state.get("rules", [])
             if isinstance(r, dict) and r.get("enabled", True)]
    return sorted(rules, key=lambda r: (r.get("priority", 100), r.get("name", "")))


# ══════════════════════════════════════════════════════════════════════════════
#  ВАЛИДАТОРЫ (для TuiField)
# ══════════════════════════════════════════════════════════════════════════════

def _rr_validate_name(text: str) -> "str | None":
    t = text.strip().lower()
    if not t:
        return "Введите имя правила"
    if not RR_NAME_RE.match(t):
        return "Имя: 2-64 символа, a-z0-9._-, начинается с буквы/цифры"
    return None


def _rr_validate_domain_item(item: str) -> "str | None":
    """Один домен-паттерн: plain / domain: / full: / regexp: / geosite:"""
    p = item.strip()
    if not p:
        return None
    low = p.lower()
    if low.startswith("geosite:"):
        # geosite-имена не содержат точку: category-ads-all, ru, youtube
        rest = p.split(":", 1)[1]
        if not rest or not re.match(r'^[a-z0-9_-]+$', rest, re.I):
            return f"После geosite: нет имени: '{p}'"
        return None
    if low.startswith(("domain:", "full:")):
        rest = p.split(":", 1)[1]
        if not rest or "." not in rest:
            return f"После префикса нет домена (с точкой): '{p}'"
        return None
    if low.startswith("regexp:"):
        rest = p.split(":", 1)[1]
        if not rest:
            return f"После regexp: нет выражения: '{p}'"
        return None
    if " " in p:
        return f"Пробелы не допускаются: '{p}'"
    if "." not in p:
        return f"'{p}' — нужен домен с точкой или префикс domain:/full:/regexp:/geosite:"
    if not re.match(r'^[a-z0-9*._-]+$', low, re.I):
        return f"Недопустимые символы в домене: '{p}'"
    return None


def _rr_validate_ip_item(item: str) -> "str | None":
    """Один элемент ip-списка: IP / CIDR / geoip:xxx."""
    p = item.strip()
    if not p:
        return None
    low = p.lower()
    if low.startswith("geoip:"):
        rest = p.split(":", 1)[1]
        if not rest or not re.match(r'^[a-z0-9_-]+$', rest, re.I):
            return f"После geoip: нет имени: '{p}'"
        return None
    try:
        ipaddress.ip_network(p, strict=False)
        return None
    except ValueError:
        return f"'{p}' — не IP/CIDR (напр. 1.2.3.0/24) и не geoip:ru"


def _rr_validate_port_item(item: str) -> "str | None":
    """Один порт или диапазон: 443 / 1000-2000."""
    p = item.strip()
    if not p:
        return None
    m = re.match(r'^(\d+)-(\d+)$', p)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if not (1 <= a < b <= 65535):
            return f"Диапазон неверен: '{p}' (нужно 1 ≤ a < b ≤ 65535)"
        return None
    if p.isdigit():
        if not (1 <= int(p) <= 65535):
            return f"Порт вне диапазона: '{p}'"
        return None
    return f"'{p}' — не порт и не диапазон (напр. 443 или 1000-2000)"


def _rr_make_list_validator(item_validator):
    """Обёртка: список через запятую; пустая строка допустима (поле опц.)."""
    def _validate(text: str) -> "str | None":
        if not text.strip():
            return None
        for part in text.split(","):
            p = part.strip()
            if not p:
                continue
            err = item_validator(p)
            if err:
                return err
        return None
    return _validate

_rr_validate_domains = _rr_make_list_validator(_rr_validate_domain_item)
_rr_validate_ips     = _rr_make_list_validator(_rr_validate_ip_item)
_rr_validate_ports   = _rr_make_list_validator(_rr_validate_port_item)


def _rr_validate_priority(text: str) -> "str | None":
    t = text.strip()
    if not t:
        return "Введите приоритет (целое, 0-9999; меньше = выше)"
    if not t.isdigit() or not (0 <= int(t) <= 9999):
        return "Приоритет: целое 0-9999"
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ XRAY
# ══════════════════════════════════════════════════════════════════════════════

def _rr_iter_configs() -> list:
    """Все живые конфиги Xray (path, cfg), dedup по realpath.
    Канон ru_subnets: патчим и /etc/xray/config.json, и альтернативный."""
    out, seen = [], set()
    for p in (_CONFIG_DIR / "config.json", _ALT_CONFIG):
        if not p.exists():
            continue
        try:
            real = str(p.resolve())
        except Exception:
            real = str(p)
        if real in seen:
            continue
        seen.add(real)
        try:
            out.append((p, json.loads(p.read_text())))
        except Exception:
            _warn(f"Не читается конфиг: {p}")
    return out


def _rr_live_outbounds() -> "tuple[list, dict]":
    """Теги outbounds из живого конфига (первый найденный)."""
    configs = _rr_iter_configs()
    if not configs:
        return [], {}
    _, cfg = configs[0]
    tags = []
    for ob in cfg.get("outbounds", []):
        t = ob.get("tag", "")
        if t:
            tags.append(t)
    return tags, cfg


def _rr_awg_exit_enabled() -> bool:
    try:
        import importlib
        core = importlib.import_module("chimera._core")
        return bool(getattr(core, "AWG_EXIT_ENABLED", False))
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  СБОРКА XRAY-ПРАВИЛ ИЗ STATE
# ══════════════════════════════════════════════════════════════════════════════

def _rr_split_ips(ips: list, chunk: int) -> list:
    """Режет ip-список на чанки (канон ru_subnets: ≤500 на правило)."""
    chunk = max(1, int(chunk or RR_DEFAULT_CHUNK))
    return [ips[i:i + chunk] for i in range(0, len(ips), chunk)] or [[]]


def _rr_build_xray_rules(rule: dict) -> "tuple[list, str]":
    """State-правило → список Xray routing rules (comment=custom:<name>).

    Возвращает ([xr_rule, ...], "") или ([], "причина отказа").
    Несколько полей в одном правиле = AND; значения в списке = OR.
    ips > chunk требует пустых domains/ports (иначе AND-семантика
    размножится на каждый чанк — молча изменив смысл правила).
    """
    name     = rule.get("name", "?")
    domains  = [d for d in rule.get("domains", []) or [] if d]
    ips      = [i for i in rule.get("ips", []) or [] if i]
    ports    = [p for p in rule.get("ports", []) or [] if p]
    outbound = rule.get("outbound", "direct")
    chunk    = int(rule.get("chunk", RR_DEFAULT_CHUNK) or RR_DEFAULT_CHUNK)
    chunk    = max(1, chunk)

    if not domains and not ips and not ports:
        return [], f"правило '{name}': нет ни одного матча"

    ip_chunks = _rr_split_ips(ips, chunk)
    multi_chunk = len(ip_chunks) > 1
    if multi_chunk and (domains or ports):
        return [], (f"правило '{name}': {len(ips)} IP разбивается на "
                    f"{len(ip_chunks)} правил по {chunk} — домены/порты при "
                    f"разбивке не поддерживаются (AND внутри правила). "
                    f"Вынесите домены/порты в отдельное правило.")

    base = {"type": "field", "outboundTag": outbound,
            "comment": f"{RR_COMMENT_PREFIX}{name}"}
    out = []
    if multi_chunk:
        for ch in ip_chunks:
            r = dict(base)
            r["ip"] = ch
            out.append(r)
        return out, ""

    r = dict(base)
    if domains:
        r["domain"] = list(domains)
    if ips:
        r["ip"] = list(ips)
    if ports:
        r["port"] = list(ports)
    out.append(r)
    return out, ""


# ══════════════════════════════════════════════════════════════════════════════
#  ПРИМЕНЕНИЕ К КОНФИГУ
# ══════════════════════════════════════════════════════════════════════════════

def _rr_is_catchall(rule: dict) -> bool:
    """Catch-all: network без доменов/IP/портов/протоколов (канон ru_subnets)."""
    if rule.get("network") not in ("tcp,udp", "tcp", "udp"):
        return False
    return not (rule.get("ip") or rule.get("domain")
                or rule.get("protocol") or rule.get("port"))


def _rr_custom_names_in_config() -> set:
    """Имена (после custom:) во всех живых конфигах."""
    names = set()
    for _path, cfg in _rr_iter_configs():
        for r in cfg.get("routing", {}).get("rules", []):
            c = r.get("comment", "")
            if c.startswith(RR_COMMENT_PREFIX):
                names.add(c[len(RR_COMMENT_PREFIX):])
    return names


def _rr_apply_to_xray(restart: bool = False, validate: bool = False,
                      silent: bool = False) -> bool:
    """Пере-применяет ВСЕ включённые правила из state в живые конфиги.

    Атомарно: сначала удаляет из routing.rules все custom:*, потом
    вставляет новые (top → в начало, before_catchall → перед catch-all).
    Если validate=True — после записи гоняет `xray run -test`; при ошибке
    откатывает конфиги к исходному тексту и возвращает False.
    restart=True — безопасный рестарт Xray (reset-failed, канон dns_rules).
    """
    configs = _rr_iter_configs()
    if not configs:
        if not silent:
            _warn("Xray конфиг не найден")
        return False

    state   = _rr_load()
    enabled = _rr_enabled_rules(state)

    # Сборка + валидация (до записи в конфиги).
    built, skipped = [], 0
    for rule in enabled:
        xr_list, err = _rr_build_xray_rules(rule)
        if err:
            if not silent:
                _warn(f"Пропуск: {err}")
            skipped += 1
            continue
        built.append((rule, xr_list))

    top_rules = []
    bc_rules  = []
    for rule, xr_list in built:
        if rule.get("placement", "top") == "before_catchall":
            bc_rules.extend(xr_list)
        else:
            top_rules.extend(xr_list)

    # Снапшоты для отката при невалидном конфиге.
    snapshots = {str(p): p.read_text() for p, _ in configs}

    for path, cfg in configs:
        try:
            routing = cfg.setdefault("routing", {})
            rules = [r for r in routing.setdefault("rules", [])
                     if not str(r.get("comment", "")).startswith(RR_COMMENT_PREFIX)]
            if bc_rules:
                idx = len(rules)
                for i, r in enumerate(rules):
                    if _rr_is_catchall(r):
                        idx = i
                        break
                rules = rules[:idx] + bc_rules + rules[idx:]
            if top_rules:
                rules = top_rules + rules
            routing["rules"] = rules
            path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(path)
        except Exception as e:
            if not silent:
                _warn(f"Ошибка патча {path}: {e}")
            return False

    # Валидация конфига живым бинарником + откат при ошибке.
    if validate:
        xray_bin = "/usr/local/bin/xray"
        for path, _ in configs:
            val = _run([xray_bin, "run", "-test", "-config", str(path)],
                       capture=True, check=False, quiet=True)
            if val.returncode != 0:
                for p2, _ in configs:
                    try:
                        p2.write_text(snapshots[str(p2)])
                        _set_config_owner(p2)
                    except Exception:
                        pass
                tail = (val.stdout + val.stderr)[-400:]
                if not silent:
                    _warn(f"Xray отклонил конфиг — откат. {tail}")
                _log("ERROR", f"apply: xray run -test failed: {tail}")
                return False

    if restart:
        _rr_reload_xray(silent=silent)

    if not silent and enabled:
        n_xray = len(top_rules) + len(bc_rules)
        _info(f"Применено правил Xray: {n_xray} из {len(enabled)} state-правил"
              + (f" (пропущено {skipped})" if skipped else ""))
    return True


def _rr_reload_xray(silent: bool = False) -> bool:
    """Безопасный рестарт (start-limit-fix, канон dns_rules/_dns_reload_xray)."""
    _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    ok = None
    for _ in range(15):
        time.sleep(1)
        ok = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if ok.stdout.strip() == "active":
            break
    if ok is not None and ok.stdout.strip() == "active":
        if not silent:
            _success("Xray перезапущен с новыми routing-правилами")
        return True
    _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    time.sleep(2)
    ok = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if ok.stdout.strip() == "active":
        if not silent:
            _success("Xray перезапущен с новыми routing-правилами")
        return True
    if not silent:
        _warn("Xray не запустился — проверьте конфиг! journalctl -u xray -n 30")
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  RESTORE (после regenerate — канон restore_youtube_rule_if_needed)
# ══════════════════════════════════════════════════════════════════════════════

def restore_routing_rules_if_needed(silent: bool = False) -> bool:
    """Пере-применяет кастомные routing-правила, если state говорит что
    они должны быть включены, но в config.json их нет (generate_*
    перезаписывает routing целиком — без restore правила молча терялись
    при каждой пересборке: смена домена/порта, regenerate 5b и т.д.).

    Отличие от youtube-канона: правил много, поэтому «уже применено» =
    ВСЕ включённые имена присутствуют в конфиге; при частичной потере —
    полный re-apply (идемпотентно: сначала удаляются все custom:*,
    потом вставляются все включённые).

    Вызывается из _core._rebuild_and_restart_xray ПОСЛЕДНИМ из
    «в начало»-вставляющих restore — итоговый порядок в конфиге:
    [custom:*] → [dns_custom:*] → [youtube] → [ru_subnets_ripe] → ...

    Перезапуск Xray делает вызывающий код. Возвращает True если
    правила были пере-применены.
    """
    state = _rr_load()
    enabled = _rr_enabled_rules(state)
    if not enabled:
        return False

    have = _rr_custom_names_in_config()
    need = {r["name"] for r in enabled}
    if need <= have:
        return False  # всё уже на месте

    missing = need - have
    if not silent:
        _info(f"Восстанавливаем кастомные routing-правила после "
              f"regenerate (потеряно: {len(missing)} из {len(need)})...")
    ok = _rr_apply_to_xray(restart=False, validate=False, silent=silent)
    if ok and not silent:
        _success(f"Кастомные routing-правила восстановлены "
                 f"({len(enabled)} правил из state)")
    return ok


# ══════════════════════════════════════════════════════════════════════════════
#  ИМПОРТ РФ-ПОДСЕТЕЙ (RIPE NCC) — запрос Vasily:
#  «правила из Split Tunneling, но вместо direct — другой outbound»
# ══════════════════════════════════════════════════════════════════════════════

_RU_SUBNETS_SOURCE = "ru_subnets_import"


def _rr_import_ru_subnets() -> "dict | None":
    """Интерактивный импорт РФ-подсетей как кастомного правила.

    Читает /etc/xray/ru_subnets_ripe.txt (split tunneling); при отсутствии
    предлагает скачать свежий delegated-ripencc-latest. Создаёт правило
    { ips: все CIDR, chunk: 500, placement: top } с выбранным outbound —
    вставляется ВЫШЕ ru_subnets_ripe, т.е. перебивает direct из Split
    Tunneling. Возвращает созданное правило-словарь или None.
    """
    print()
    _box_top("Импорт РФ подсетей (RIPE NCC) → кастомный outbound")
    _box_row()
    _box_desc("Правила Split Tunneling (ru_subnets_ripe) направляют РФ-подсети")
    _box_desc("в direct. Это правило делает то же самое, но в выбранный outbound")
    _box_desc("(напр. chain-exit-N) — вставляется ВЫШЕ ru_subnets_ripe и BLOCK,")
    _box_desc("поэтому перебивает direct. Домены/порты не задаются.")
    _box_row()
    _box_bottom()

    # 1. Список CIDR
    cidrs = []
    try:
        from chimera.modules.ru_subnets import _ru_subnets_load_from_file
        cidrs = _ru_subnets_load_from_file()
    except Exception:
        try:
            f = Path("/etc/xray/ru_subnets_ripe.txt")
            if f.exists():
                cidrs = [l.strip() for l in f.read_text().splitlines()
                         if l.strip() and not l.startswith("#")]
        except Exception:
            cidrs = []

    if not cidrs:
        ans = _box_ask("Файл РФ-подсетей пуст/нет. Скачать из RIPE NCC сейчас? [y/N]")
        if ans.strip().lower() != "y":
            _warn("Импорт отменён: нет списка подсетей.")
            return None
        try:
            from chimera.modules import ru_subnets as rs
            fetched = rs._fetch_ru_subnets_from_ripe()
            if not fetched:
                _warn("RIPE NCC недоступен — импорт отменён.")
                return None
            rs._ru_subnets_save(fetched)
            cidrs = fetched
        except Exception as e:
            _warn(f"Не удалось скачать: {e}")
            return None

    _info(f"Подсетей РФ: {len(cidrs)} (→ {(len(cidrs) + 499) // 500} правил Xray по 500)")

    # 2. Outbound
    tags, _cfg = _rr_live_outbounds()
    if not tags:
        _warn("Нет живого конфига Xray — сначала установка.")
        return None
    options = [f"{t}  ({'freedom' if t in ('direct', 'direct-local') else 'внешняя нода' if t.startswith('chain-exit') else 'blackhole' if t in ('block', 'BLOCK') else 'outbound'})" for t in tags]
    options.append("— Ввести тег вручную —")
    idx = tui_select("Куда направить трафик РФ-подсетей?", options)
    if idx is None:
        return None
    if idx == len(options) - 1:
        res = tui_form("Outbound вручную", [
            TuiField(key="tag", label="Тег outbound", required=True,
                     hint="Напр. chain-exit-4 или my-outbound"),
        ])
        if not res:
            return None
        outbound = res["tag"].strip()
    else:
        outbound = tags[idx]

    # 3. Имя правила
    default_name = f"ru-subnets-via-{outbound}".lower()[:64]
    existing = {r.get("name") for r in _rr_load().get("rules", [])}
    if default_name in existing:
        default_name = f"{default_name}-{len(existing) + 1}"
    res = tui_form("Имя правила", [
        TuiField(key="name", label="Имя", default=default_name,
                 required=True, validator=_rr_validate_name,
                 hint="Идентификатор в comment=custom:<имя>"),
        TuiField(key="priority", label="Приоритет", default="10",
                 required=True, validator=_rr_validate_priority,
                 hint="Меньше = выше в конфиге"),
    ])
    if not res:
        return None
    name = res["name"].strip().lower()

    rule = {
        "name": name,
        "enabled": True,
        "domains": [],
        "ips": sorted(cidrs),
        "ports": [],
        "outbound": outbound,
        "priority": int(res["priority"]),
        "placement": "top",
        "chunk": RR_DEFAULT_CHUNK,
        "source": _RU_SUBNETS_SOURCE,
        "created_at": _rr_now(),
        "updated_at": _rr_now(),
    }

    # Сводка + подтверждение
    print()
    _box_top(f"Правило: {name}")
    _box_kv("Матч", f"РФ подсети RIPE ({len(cidrs)} CIDR)")
    _box_kv("Outbound", outbound)
    _box_kv("Приоритет", str(rule["priority"]))
    _box_kv("Расположение", "top (выше ru_subnets_ripe)")
    _box_kv("Правил Xray", f"{(len(cidrs) + 499) // 500} (по 500 CIDR)")
    _box_row()
    _box_warn("  Правило действует на всех клиентов сервера сразу (routing Xray")
    _box_warn("  не разделяет трафик по пользователям).")
    _box_bottom()
    if not tui_confirm("Создать правило и применить?", default=False):
        return None

    state = _rr_load()
    state.setdefault("rules", []).append(rule)
    _rr_save(state)
    _log_change(f"rule_add:{name}", f"РФ подсети ({len(cidrs)}) → {outbound}")
    _rr_apply_to_xray(restart=True, validate=True)
    return rule


def _log_change(key: str, detail: str) -> None:
    """Пишет в /var/lib/xray-installer/changes.json (канон _core._log_change)."""
    try:
        ch_file = Path("/var/lib/xray-installer/changes.json")
        entries = []
        if ch_file.exists():
            try:
                entries = json.loads(ch_file.read_text())
                if not isinstance(entries, list):
                    entries = []
            except Exception:
                entries = []
        entries.append({"ts": _rr_now(), "key": key, "detail": detail})
        ch_file.parent.mkdir(parents=True, exist_ok=True)
        ch_file.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  ОТОБРАЖЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════

def _rr_match_summary(rule: dict, max_len: int = 34) -> str:
    """Компактная строка матча для списка: 'd:2 ip:500 p:1'."""
    d = len(rule.get("domains") or [])
    i = len(rule.get("ips") or [])
    p = len(rule.get("ports") or [])
    parts = []
    if d:
        parts.append(f"d:{d}")
    if i:
        tag = "geoip" if any(str(x).startswith("geoip:") for x in rule["ips"]) else "cidr"
        parts.append(f"{tag}:{i}")
    if p:
        parts.append(f"p:{p}")
    return " ".join(parts) if parts else "—"


def _rr_show_live_rules() -> None:
    os.system("clear")
    print()
    _box_top("Живые кастомные правила в конфиге (custom:*)")
    configs = _rr_iter_configs()
    if not configs:
        _box_row(f"  {DIM}Конфиг не найден{NC}")
        _box_bottom()
        return
    for path, cfg in configs:
        _box_row(f"  {BOLD}{path}{NC}")
        rules = [r for r in cfg.get("routing", {}).get("rules", [])
                 if str(r.get("comment", "")).startswith(RR_COMMENT_PREFIX)]
        if not rules:
            _box_row(f"    {DIM}— нет custom:* правил —{NC}")
            continue
        for pos, r in enumerate(rules, 1):
            name = str(r.get("comment", ""))[len(RR_COMMENT_PREFIX):]
            ob   = r.get("outboundTag", "?")
            nd   = len(r.get("domain") or [])
            ni   = len(r.get("ip") or [])
            np_  = len(r.get("port") or [])
            mat = " ".join(x for x in (f"d:{nd}" if nd else "",
                                       f"ip:{ni}" if ni else "",
                                       f"p:{np_}" if np_ else "") if x) or "—"
            col = GREEN if r.get("enabled", True) is not False else DIM
            _box_row(f"    #{pos:<3} {CYAN}{name:<32}{NC} → {GREEN}{ob}{NC}  {DIM}{mat}{NC}")
        _box_sep()
    _box_row(f"  {DIM}dns_custom:* / ru_subnets_ripe / youtube — встроенные, тут не показаны{NC}")
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════

def do_manage_routing_rules() -> None:
    """Меню управления кастомными routing-правилами."""
    while True:
        os.system("clear")
        state   = _rr_load()
        rules   = state.get("rules", [])
        enabled = [r for r in rules if r.get("enabled", True)]
        in_cfg  = _rr_custom_names_in_config()
        need    = {r["name"] for r in enabled}
        lost    = need - in_cfg
        extra   = in_cfg - need

        print()
        _box_top("🧭  КАСТОМНЫЕ ROUTING-ПРАВИЛА")
        _box_row()
        _box_row(f"  {BOLD}Правил: {len(rules)}{NC}  {DIM}(включено {len(enabled)}, "
                 f"в конфиге {len(in_cfg)}){NC}")
        if rules:
            _box_sep()
            shown = 0
            for r in sorted(rules, key=lambda x: (x.get("priority", 100), x.get("name", ""))):
                if shown >= 8:
                    _box_row(f"  {DIM}... ещё {len(rules) - 8} правил{NC}")
                    break
                shown += 1
                on    = r.get("enabled", True)
                dot   = f"{GREEN}●{NC}" if on else f"{DIM}○{NC}"
                name  = r.get("name", "?")
                ob    = r.get("outbound", "?")
                prio  = r.get("priority", 100)
                mat   = _rr_match_summary(r)
                plac  = "↑top" if r.get("placement", "top") != "before_catchall" else "↓pre-catchall"
                obcol = GREEN if ob in ("direct", "direct-local") else (
                    RED if ob in ("block", "BLOCK") else CYAN)
                _box_row(f"  {dot} {CYAN}{name:<28}{NC} {DIM}p{prio:<3}{NC} "
                         f"{mat:<16} → {obcol}{ob}{NC}  {DIM}{plac}{NC}")
        if lost:
            _box_sep()
            _box_row(f"  {RED}⚠  Потеряно в конфиге: {len(lost)}{NC}  "
                     f"{DIM}(regenerate стёр — пункт 7 восстановит){NC}")
        _box_row()
        _box_desc("Матч: домены / IP+CIDR / порты. Поля в одном правиле = AND,")
        _box_desc("значения в списке = OR. Большие IP-списки режутся по 500.")
        _box_desc(f"{YELLOW}⚠  Правила действуют на всех клиентов сервера сразу.{NC}")
        _box_row()
        _box_item("1", "Добавить правило")
        _box_item("2", "Изменить правило")
        _box_item("3", "Вкл / выкл правило")
        _box_item("4", "Удалить правило")
        _box_item("5", f"Импорт РФ-подсетей (RIPE)  {DIM}→ любой outbound вместо direct{NC}")
        _box_item("6", "Показать живые правила из конфига (custom:*)")
        _box_item("7", "Пере-применить все правила из state (после regenerate)")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            _rr_menu_add_rule()
        elif ch == "2":
            _rr_menu_edit_rule()
        elif ch == "3":
            _rr_menu_toggle_rule()
        elif ch == "4":
            _rr_menu_delete_rule()
        elif ch == "5":
            _rr_import_ru_subnets()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            _rr_show_live_rules()
        elif ch == "7":
            print()
            ok = _rr_apply_to_xray(restart=True, validate=True)
            if ok:
                _success("Все правила из state пере-применены")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", ""):
            break
        else:
            _warn("Неверный выбор")
            time.sleep(1)


# ── Подменю: добавление / изменение ──────────────────────────────────────────

_AWG_HINT_SHOWN = False


def _rr_menu_add_or_edit(existing: "dict | None" = None) -> "dict | None":
    """Общий flow добавления (existing=None) / изменения (existing=rule).

    Возвращает готовое правило-словарь или None (отмена). НЕ сохраняет.
    """
    global _AWG_HINT_SHOWN
    is_edit = existing is not None
    state   = _rr_load()
    others  = {r.get("name") for r in state.get("rules", [])
               if not is_edit or r.get("name") != existing.get("name")}

    awg = _rr_awg_exit_enabled()
    if awg and not _AWG_HINT_SHOWN and not is_edit:
        _AWG_HINT_SHOWN = True
        print()
        _box_top("Подсказка (AWG-режим)")
        _box_row()
        _box_row(f"  Транспорт AWG активен: {CYAN}direct{NC} идёт через туннель awg0 → exit-VPS,")
        _box_row(f"  {CYAN}direct-local{NC} — через default route ОС (как ru_subnets в AWG).")
        _box_bottom()

    # ── Шаг 1: форма (имя, матчи, приоритет) ──
    f_default = (existing or {}).get
    while True:
        form = tui_form(
            "Изменить правило" if is_edit else "Новое правило — матч и приоритет",
            [
                TuiField(key="name", label="Имя", default=f_default("name", ""),
                         required=True, validator=_rr_validate_name,
                         hint="a-z0-9._- ; идентификатор в comment=custom:<имя>"),
                TuiField(key="domains", label="Домены", default=", ".join(f_default("domains", []) or []),
                         validator=_rr_validate_domains,
                         hint="example.com, domain:google.com, geosite:category-ads-all"),
                TuiField(key="ips", label="IP / CIDR", default=", ".join(f_default("ips", []) or []),
                         validator=_rr_validate_ips,
                         hint="1.2.3.0/24, 5.6.7.8, geoip:ru — пусто = нет"),
                TuiField(key="ports", label="Порты", default=", ".join(f_default("ports", []) or []),
                         validator=_rr_validate_ports,
                         hint="443, 1000-2000 — пусто = нет"),
                TuiField(key="priority", label="Приоритет", default=str(f_default("priority", 10)),
                         required=True, validator=_rr_validate_priority,
                         hint="Меньше = выше в конфиге (раньше матчится)"),
            ],
        )
        if form is None:
            return None

        name = form["name"].strip().lower()
        if name in others:
            _warn(f"Имя '{name}' уже занято другим правилом")
            continue

        domains = _split_list(form.get("domains", ""))
        ips     = _split_list(form.get("ips", ""))
        ports   = _split_list(form.get("ports", ""))
        if not domains and not ips and not ports:
            _warn("Хотя бы один матч: домены, IP/CIDR или порты")
            continue

        n_ip_chunks = (len(ips) + RR_DEFAULT_CHUNK - 1) // RR_DEFAULT_CHUNK or 1
        if n_ip_chunks > 1 and (domains or ports):
            _warn(f"{len(ips)} IP режется на {n_ip_chunks} правил по "
                  f"{RR_DEFAULT_CHUNK} — домены/порты при разбивке не "
                  f"поддерживаются. Вынесите их в отдельное правило.")
            continue
        break

    # ── Шаг 2: outbound ──
    tags, _cfg = _rr_live_outbounds()
    cur_out = f_default("outbound", "direct")
    outbound = None
    if tags:
        options = list(tags) + ["— Ввести тег вручную —"]
        try:
            pre = tags.index(cur_out)
        except ValueError:
            pre = 0
        idx = tui_select("Outbound (куда направить трафик)", options, default=pre)
        if idx is None:
            return None
        if idx == len(options) - 1:
            manual = tui_form("Outbound вручную", [
                TuiField(key="tag", label="Тег", default=cur_out, required=True,
                         hint="Напр. chain-exit-4"),
            ])
            if manual is None:
                return None
            outbound = manual["tag"].strip()
        else:
            outbound = tags[idx]
    else:
        manual = tui_form("Outbound (нет живого конфига)", [
            TuiField(key="tag", label="Тег", default=cur_out, required=True),
        ])
        if manual is None:
            return None
        outbound = manual["tag"].strip()

    # ── Шаг 3: расположение ──
    cur_plac = f_default("placement", "top") or "top"
    plac_idx = tui_select(
        "Расположение правила в routing.rules",
        [
            "top — в начало: ВЫШЕ dns_custom/ru_subnets/youtube (перебивает встроенные)",
            "before_catchall — перед catch-all в конце: ПОСЛЕ встроенных",
        ],
        default=0 if cur_plac != "before_catchall" else 1,
    )
    if plac_idx is None:
        return None
    placement = "top" if plac_idx == 0 else "before_catchall"

    # ── Сборка ──
    rule = {
        "name": name,
        "enabled": f_default("enabled", True),
        "domains": domains,
        "ips": ips,
        "ports": ports,
        "outbound": outbound,
        "priority": int(form["priority"]),
        "placement": placement,
        "chunk": int(f_default("chunk", RR_DEFAULT_CHUNK) or RR_DEFAULT_CHUNK),
        "source": f_default("source", "manual"),
        "created_at": f_default("created_at", _rr_now()),
        "updated_at": _rr_now(),
    }
    if is_edit:
        rule["enabled"] = existing.get("enabled", True)

    # ── Сводка ──
    xr_list, err = _rr_build_xray_rules(rule)
    print()
    _box_top(f"{'Изменение' if is_edit else 'Новое'} правило: {name}")
    _box_kv("Матч (AND между полями)", _rr_match_summary(rule))
    if domains:
        _box_kv("  домены", ", ".join(domains[:4]) + (" ..." if len(domains) > 4 else ""))
    if ips:
        _box_kv("  ip/cidr", f"{len(ips)} шт" + (f" (→ {len(xr_list)} правил по {rule['chunk']})" if len(xr_list) > 1 else ""))
    if ports:
        _box_kv("  порты", ", ".join(ports[:4]) + (" ..." if len(ports) > 4 else ""))
    _box_kv("Outbound", outbound)
    _box_kv("Приоритет", str(rule["priority"]))
    _box_kv("Расположение", placement + (" (выше встроенных)" if placement == "top" else " (перед catch-all)"))
    if err:
        _box_row()
        _box_warn(f"  {err}")
    _box_bottom()
    return rule


def _split_list(text: str) -> list:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def _rr_menu_add_rule() -> None:
    rule = _rr_menu_add_or_edit(existing=None)
    if not rule:
        return
    if not tui_confirm("Добавить и применить сейчас?", default=True):
        # Сохранить без применения — предупредить о состоянии
        state = _rr_load()
        state.setdefault("rules", []).append(rule)
        _rr_save(state)
        _warn("Сохранено БЕЗ применения — в конфиге появится по пункту 7")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    state = _rr_load()
    state.setdefault("rules", []).append(rule)
    _rr_save(state)
    _log_change(f"rule_add:{rule['name']}",
                f"{rule.get('source','manual')} → {rule['outbound']}")
    _rr_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _rr_pick_rule(prompt: str, only_enabled: bool = False) -> "dict | None":
    state = _rr_load()
    rules = state.get("rules", [])
    pool = [r for r in rules if (r.get("enabled", True) or not only_enabled)] \
        if only_enabled else list(rules)
    if not pool:
        _warn("Нет правил в state")
        return None
    options = []
    for r in sorted(pool, key=lambda x: (x.get("priority", 100), x.get("name", ""))):
        on = "●" if r.get("enabled", True) else "○"
        options.append(f"[{on}] {r.get('name','?'):<28} → {r.get('outbound','?')}"
                       f"  {_rr_match_summary(r)}")
    idx = tui_select(prompt, options)
    if idx is None:
        return None
    return pool[idx]


def _rr_menu_edit_rule() -> None:
    target = _rr_pick_rule("Какое правило изменить?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    old_name = target.get("name")
    updated = _rr_menu_add_or_edit(existing=target)
    if not updated:
        return
    state = _rr_load()
    for i, r in enumerate(state.get("rules", [])):
        if r.get("name") == old_name:
            state["rules"][i] = updated
            break
    _rr_save(state)
    _log_change(f"rule_edit:{updated['name']}", f"было {old_name}")
    if not tui_confirm("Применить изменения (патч конфига + рестарт)?", default=True):
        _warn("Сохранено в state; в конфиге — по пункту 7")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    _rr_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _rr_menu_toggle_rule() -> None:
    target = _rr_pick_rule("Какое правило включить/выключить?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    name = target.get("name")
    state = _rr_load()
    for r in state.get("rules", []):
        if r.get("name") == name:
            r["enabled"] = not r.get("enabled", True)
            r["updated_at"] = _rr_now()
            new_val = r["enabled"]
            break
    else:
        return
    _rr_save(state)
    _log_change(f"rule_toggle:{name}", f"enabled={new_val}")
    _rr_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _rr_menu_delete_rule() -> None:
    target = _rr_pick_rule("Какое правило удалить?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    name = target.get("name")
    if not tui_confirm(f"Удалить правило '{name}'?", default=False):
        return
    state = _rr_load()
    state["rules"] = [r for r in state.get("rules", []) if r.get("name") != name]
    _rr_save(state)
    _log_change(f"rule_del:{name}", "удалено")
    # apply удалит его из конфига (custom:* удаляются все, вставляются включённые)
    _rr_apply_to_xray(restart=True, validate=True)
    _success(f"Правило '{name}' удалено")
    input(f"{BLUE}Нажмите Enter...{NC}")
