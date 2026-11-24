"""
chimera/modules/rkn_guard.py
───────────────────────────────────────────────────────────────────────────────
RKN-Guard — фильтрация входящего трафика по подсетям РКН/ТСПУ/СКИПА/сканеров.

Порт проекта Flecksis/rkn-guard (Go, MIT, v4.0.x) в TUI Chimera: бинарник
rkn-guard ставится на ноду как вендорный инструмент, а ВСЁ управление —
установка, списки, расписание, баны, исключения, статистика, панель,
обновления, смена firewall-бэкенда, переустановка/удаление — из меню
«Безопасность и автоматизация» [RG], в стиле Chimera.

Зачем (кейс <entry-de> 2026-11): ТСПУ душит sustained-потоки в транзите
(снимается каскадом Mieru), но остаётся вектор попадания ноды в реестры —
сканеры РКН/СКИПА подключаются к открытым портам и пробуют рукопожатия.
rkn-guard дропает SYN от известных подсетей на входе: сканер видит «хост
не отвечает», признаков прокси нет. Списки прицельные (5 базовых,
~4.4k CIDR): гос-сети, ручные сканеры (195.209.123.x и семейство),
СКИПА-пойнты, ТСПУ-оборудование (109.124.x), CyberOK — потребительские
AS НЕ затронуты, дом-клиенты проходят.

Механика (iptables-бэкенд — дефолт, вся Химера на iptables/ipset):
  • сеты ipset  SCANNERS-BLOCK-V4 / SCANNERS-BLOCK-V6 (hash:net,
    лимит 65536 подсетей на семейство — проверка бинарника)
  • цепочка      SCANNERS-BLOCK (filter): ESTABLISHED,RELATED return →
    [LOG rate 10/min] → DROP по match-set src; при активном UFW цепочка
    вешается в ufw-before-input ЧЕРЕЗ managed-блок в /etc/ufw/before.rules
    («# SCANNERS-BLOCK chain - managed by antiscan»), при неактивном —
    первой строкой INPUT; счётчики дропов не сбрасываются при update
    (сеты меняются swap'ом, правила не пересоздаются)
  • UFW-jump авторековери (кейс <blw> 24.11): после `ufw reload` бинарник
    требует, чтобы jump был ПЕРВЫМ правилом живой ufw-before-input; если
    внешняя система (антидос/телеметрия хостера) успевает вставить своё
    правило в начало цепочки — установка падает «SCANNERS-BLOCK is not
    the first rule». Обёртка _rg_cli_mutate_ufw_safe сама переставляет
    jump на 1-е место и повторяет операцию (fast-path, без reload).
    Усугубляющий фактор (доп. от <blw>): раздутый ruleset — ~63k
    индивидуальных DROP от стороннего пер-IP бана; на nf_tables каждый
    вызов iptables обрабатывает ruleset целиком → reload/verify
    медленные, окно гонки широкое (после чистки мусора вставало).
    Поэтому диагностика повторного провала включает подсчёт правил
    (iptables-save | grep -c '^-A') — десятки тысяч = чужой мусор.
  • восстановление при ребуте: antiscan-ipset-restore.service
    (ipset restore -exist -f /etc/ipset.conf, Before=ufw.service) +
    antiscan-move-rules.service (перестановка jump на 1-е место)
  • статистика: rsyslog → /var/log/iptables-scanners-{ipv4,ipv6}.log →
    antiscan-aggregate.timer (30с) → ...-aggregate.csv (ASN/netname)
  • nftables/firewalld-бэкенды доступны как опция (отдельная таблица
    inet rkn_guard, hook input priority -10) — на Химере не дефолт

ИНТЕГРАЦИЯ С /etc/ipset.conf (КРИТИЧНО, см. _rg_ipset_conf_merge):
  rkn-guard при каждом full/update/uninstall ПЕРЕЗАПИСЫВАЕТ /etc/ipset.conf
  ЦЕЛИКОМ, причём записывает ТОЛЬКО свои секции SCANNERS-BLOCK-* — а файл
  ОБЩИЙ с Химерой (ipset_persist: xray_ru_block*, ipban: xray_manual_ban*,
  ingress_geoip/geoblock/user_ip_whitelist). Их uninstall вообще удаляет
  файл — ConditionPathExists=xray-ipset-restore.service молча пропускает
  восстановление → химерные сеты тихо пустеют при ребуте (класс кейса
  «тихого испарения бана ГРЧЦ», окт.2026, — см. шапку ipset_persist.py).
  Поэтому КАЖДАЯ мутирующая операция rkn-guard в этом модуле (и таймер
  автообновления через main.py --rkn-update) обёрнута снапшотом-слиянием:
  перед операцией читаем файл, после — сшиваем: свежие секции rkn-guard +
  чужие (химерные) секции ДОСЛОВНО из снапшота. Атомарно (tmp+rename).

Синхронизация с апстримом (требование владельца):
  • списки — таймер rkn-guard-update.timer (наш юнит: ExecStart →
    main.py --rkn-update → update --managed-lists + merge-компенсация),
    режимы: каждые N часов / список времён МСК / ежедневно 06:00 МСК /
    06:00 локального времени / выкл; частичное обновление rc=2 — предупреж
    даем, наборы не откатываются (кэши источников остаются)
  • бинарник — пункт «U»: сверка тега GitHub Releases с build-info,
    скачивание через зеркало-лестницу (release GitHub → gh-proxy×3 →
    ручной /root), setup-logging после обновления; опция сборки из
    исходников ветки master/dev (git+go, если toolchain на ноде)
  • панель rkn-guard-panel (Windows): привязка «panel issue» (код RKN1,
    5 минут, SSH-адрес/порт из текущего SSH-сеанса) и отзыв «panel revoke»

Точки входа:
    from chimera.modules.rkn_guard import (
        do_manage_rkn_guard, rkn_cli_update,
    )
    _core.py: меню [RG] «Безопасность и автоматизация»
    main.py: python3 main.py --rkn-update  (ExecStart таймера)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# ── Цвета ─────────────────────────────────────────────────────────────────────
# Канон: импорт из box_renderer (единый источник полноценных ANSI-кодов).
# Локальная копия с голым ESC-байтом ('\033' без [0;31m) ломала и рамки, и
# текст: _wcslen не срезает голый ESC (фантомная ширина → правая ║ ехала
# лесенкой), а терминалы клиентов глотали ESC+следующий символ как начало
# escape-последовательности — «Выбор»→«ыбор», «Порт»→«орт», «v4.0.1»→
# «4.0.1» (инцидент 24.11, скрин владельца).
from chimera.modules.box_renderer import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, WHITE, NC,
)

# ── Пути и константы ──────────────────────────────────────────────────────────
RG_BIN               = Path("/usr/local/bin/rkn-guard")
RG_STATE_FILE        = Path("/var/lib/xray-installer/rkn_guard.json")
RG_SOURCES_FILE      = Path("/var/lib/rkn-guard/sources.json")      # state rkn-guard
RG_FIREWALL_CONF     = Path("/etc/rkn-guard-firewall.json")        # backend+logging
RG_SCHEDULE_CONF     = Path("/etc/rkn-guard-update.conf")          # mode=value
RG_TIMER             = "rkn-guard-update.timer"
RG_SERVICE           = "rkn-guard-update.service"
RG_TIMER_PATH        = Path(f"/etc/systemd/system/{RG_TIMER}")
RG_SERVICE_PATH      = Path(f"/etc/systemd/system/{RG_SERVICE}")
RG_MANUAL_FILE       = Path("/opt/rkn-guard-manual.list")          # ручные баны
RG_PANEL_DIR         = Path("/var/lib/rkn-guard-panel")            # привязка панели
RG_LOG_V4            = Path("/var/log/iptables-scanners-ipv4.log")
RG_LOG_V6            = Path("/var/log/iptables-scanners-ipv6.log")
RG_AGGREGATE_CSV     = Path("/var/log/iptables-scanners-aggregate.csv")
RG_LOG_FILE          = Path("/var/log/chimera.log")

# Общий с Химерой ipset-персистенс (см. _rg_ipset_conf_merge):
IPSET_CONF           = Path("/etc/ipset.conf")
# Сеты/цепочка rkn-guard:
_RGN_SETS            = ("SCANNERS-BLOCK-V4", "SCANNERS-BLOCK-V6")
_RGN_CHAIN           = "SCANNERS-BLOCK"
_RGN_TABLE_NFT       = "inet rkn_guard"

RG_UPSTREAM_REPO     = "Flecksis/rkn-guard"
RG_UPSTREAM_API      = "https://api.github.com/repos/Flecksis/rkn-guard/releases/latest"
RG_PANEL_APP_URL     = "https://github.com/Flecksis/rkn-guard-panel/releases/latest"

# Базовые списки апстрима (нормализованные URL — как их видит rkn-guard
# в sources.json: host lowercase, refs/heads выпущен). Порядок = номер
# базового списка в CLI (sources base-enable N — N по порядку --base-url).
RG_BASE_DEFAULTS: list[dict] = [
    {"key": "gov",       "label": "Гос-сети РКН",
     "url": "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/government_networks.list"},
    {"key": "scan",      "label": "Ручные сканеры РКН",
     "url": "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/antiscanner.list"},
    {"key": "skipa",     "label": "СКИПА-пойнты",
     "url": "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/skipa.list"},
    {"key": "c24",       "label": "AS-сети ТСПУ (C24Be)",
     "url": "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt"},
    {"key": "cyberok",   "label": "СКИПА (CyberOK)",
     "url": "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"},
]

_FIREWALL_LABELS = {
    "iptables":  "iptables + ipset",
    "nftables":  "nftables",
    "firewalld": "firewalld + nftables",
}


# ── Логирование ────────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    """Пишет в /var/log/chimera.log с префиксом [RG]."""
    try:
        RG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with RG_LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{ts} [RG] {level}: {msg}\n")
    except Exception:
        pass  # лог не должен ронять операцию


def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}   {msg}"); _log("INFO", msg)
def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}     {msg}"); _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}   {msg}"); _log("WARN", msg)
def _err(msg: str)     -> None: print(f"{RED}[ERR]{NC}    {msg}"); _log("ERR", msg)


def _core_module():
    """Возвращает модуль chimera._core (лениво, как в ru_subnets.py)."""
    import importlib
    return importlib.import_module("chimera._core")


def _tg_notify_event(event: str, detail: str = "") -> None:
    """Делегация TG-уведомления в _core; no-op если недоступен."""
    try:
        _core_module()._tg_notify_event(event, detail)
    except Exception:
        pass


# ── subprocess ─────────────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, quiet: bool = False,
         timeout: int = 120) -> subprocess.CompletedProcess:
    """subprocess.run без исключений (таймаут/отсутствие бинарника → rc!=0)."""
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                   errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return subprocess.run(cmd, timeout=timeout, **kw)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        _log("WARN", f"cmd failed: {' '.join(cmd[:3])}…: {e}")
        return subprocess.CompletedProcess(cmd, 124, "", str(e))


def _rg_run(args: list, timeout: int = 300) -> subprocess.CompletedProcess:
    """Запуск rkn-guard CLI (capture stdout+stderr всегда — контроль вывода)."""
    return _run([str(RG_BIN), *args], capture=True, timeout=timeout)


def _input(prompt: str, default: str = "") -> str:
    """input() с защитой от EOF/Ctrl+C — возвращает default."""
    try:
        val = input(prompt).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        return default


def _confirm(prompt: str, default_yes: bool = False) -> bool:
    hint = "[Y/n]" if default_yes else "[y/N]"
    while True:
        ans = _input(f"{BOLD}{prompt} {hint}:{NC} ").lower()
        if ans == "":
            return default_yes
        if ans in ("y", "yes", "д", "да"):
            return True
        if ans in ("n", "no", "н", "нет"):
            return False
        print(f"{DIM}  Введите y или n.{NC}")


# ═════════════════════════════════════════════════════════════════════════════
#  НОРМАЛИЗАЦИЯ URL (зеркало Go NormalizeSourceURL — для соответствия ключей
#  sources.json) + ВАЛИДАЦИЯ
# ═════════════════════════════════════════════════════════════════════════════
def _rg_norm_url(raw: str) -> str:
    """Нормализация URL источника как в rkn-guard (ключ кэша sources.json).

    GitHub blob → raw, refs/heads выпускается, host lowercase.
    Бросает ValueError при невалидном URL.
    """
    raw = raw.strip()
    if not raw or len(raw) > 4096 or re.search(r"[\s\x00-\x1f]", raw):
        raise ValueError("URL без пробелов и управляющих символов")
    u = urlsplit(raw)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("нужен HTTP(S) URL")
    if u.username is not None or u.fragment:
        raise ValueError("URL без пароля и фрагмента #")
    host = u.hostname.lower()
    path = u.path or ""
    parts = [p for p in path.split("/") if p]
    query = u.query
    if host == "github.com" and len(parts) >= 5 and parts[2] == "blob":
        host = "raw.githubusercontent.com"
        path = "/" + "/".join([*parts[:2], *parts[3:]])
        query = ""
    elif host == "raw.githubusercontent.com" and \
            len(parts) >= 6 and parts[2] == "refs" and parts[3] == "heads":
        path = "/" + "/".join([*parts[:2], *parts[4:]])
    netloc = host if u.port is None else f"{host}:{u.port}"
    return urlunsplit((u.scheme, netloc, path, query, ""))


# ═════════════════════════════════════════════════════════════════════════════
#  STATE (наш): base_urls + предпочтения установки. Включённость списков
#  читаем напрямую из sources.json rkn-guard (единый источник истины).
# ═════════════════════════════════════════════════════════════════════════════
def _rg_state_default() -> dict:
    return {
        "enabled":         False,
        "installed_at":    "",
        "version":         "",
        "branch":          "master",
        "firewall":        "iptables",     # дефолт: вся Химера на iptables/ipset
        "logging":         True,
        "base_urls":       [dict(e) for e in RG_BASE_DEFAULTS],
        "schedule_mode":   "off",
        "schedule_value":  "",
        "last_update":     "",
    }


def _rg_state_load() -> dict:
    try:
        st = json.loads(RG_STATE_FILE.read_text())
        if isinstance(st, dict):
            base = st.get("base_urls")
            if not isinstance(base, list) or not base:
                st["base_urls"] = [dict(e) for e in RG_BASE_DEFAULTS]
            return {**_rg_state_default(), **st}
    except FileNotFoundError:
        pass
    except Exception as e:
        _log("WARN", f"state битый, дефолт: {e}")
    return _rg_state_default()


def _rg_state_save(st: dict) -> None:
    try:
        RG_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = RG_STATE_FILE.with_suffix(".json.new")
        tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2))
        os.replace(tmp, RG_STATE_FILE)
    except Exception as e:
        _warn(f"Не удалось сохранить state: {e}")


def _rg_base_urls(st: dict | None = None) -> list[str]:
    """Базовые URL (наш state → /etc/rkn-guard-sources.list → дефолты)."""
    if st is None:
        st = _rg_state_load()
    urls = []
    for e in st.get("base_urls", []):
        try:
            urls.append(_rg_norm_url(e["url"]))
        except Exception:
            continue
    if urls:
        return urls
    # Fallback: standalone-установка их bash-меню — файл замены базовых URL
    try:
        legacy = [l.split("#")[0].strip()
                  for l in Path("/etc/rkn-guard-sources.list").read_text().splitlines()]
        legacy = [l for l in legacy if l]
        if legacy:
            out = []
            for l in legacy:
                try:
                    out.append(_rg_norm_url(l))
                except Exception:
                    continue
            if out:
                return out
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return [_rg_norm_url(e["url"]) for e in RG_BASE_DEFAULTS]


def _base_url_args() -> list[str]:
    """Флаги --base-url/--urls для полного списка базовых источников."""
    args: list[str] = []
    for u in _rg_base_urls():
        args += ["--urls", u]
    return args


# ═════════════════════════════════════════════════════════════════════════════
#  ЧТЕНИЕ STATE rkn-guard (sources.json / firewall.json / расписание)
# ═════════════════════════════════════════════════════════════════════════════
def _rg_sources_state() -> dict:
    """state источников rkn-guard: extra[], cache{url:…}, disabled_base{url:…}."""
    try:
        return json.loads(RG_SOURCES_FILE.read_text())
    except Exception:
        return {}


def _rg_base_enabled(url_norm: str, src_state: dict) -> bool:
    return not bool((src_state.get("disabled_base") or {}).get(url_norm))


def _rg_fw_state() -> dict:
    """/etc/rkn-guard-firewall.json: {backend, logging, networks:{…}}."""
    try:
        return json.loads(RG_FIREWALL_CONF.read_text())
    except Exception:
        return {}


def _rg_backend() -> str:
    return str(_rg_fw_state().get("backend", "iptables"))


def _rg_installed() -> bool:
    return RG_BIN.exists() and os.access(RG_BIN, os.X_OK)


def _rg_version() -> tuple[str, str]:
    """(version, branch) из build-info; ('', '') при провале."""
    r = _rg_run(["build-info"], timeout=20)
    lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
    if r.returncode == 0 and len(lines) >= 2:
        return lines[0].strip(), lines[1].strip()
    return "", ""


def _rg_rules_active() -> bool:
    """Живы ли правила (цепочка iptables или таблица nft)."""
    backend = _rg_backend()
    if backend == "iptables":
        r = _run(["iptables", "-w", "-S", _RGN_CHAIN], capture=True, timeout=10)
        return r.returncode == 0 and bool((r.stdout or "").strip())
    r = _run(["nft", "list", "table", _RGN_TABLE_NFT], capture=True, timeout=10)
    return r.returncode == 0


def _rg_set_size(name: str) -> int:
    r = _run(["ipset", "list", name], capture=True, timeout=10)
    m = re.search(r"Number of entries:\s*(\d+)", r.stdout or "")
    return int(m.group(1)) if m else 0


def _rg_subnets_total() -> tuple[int, str]:
    """(всего подсетей, дата обновления МСК) — из сетов/файла firewall.json."""
    backend = _rg_backend()
    if backend == "iptables":
        total = _rg_set_size(_RGN_SETS[0]) + _rg_set_size(_RGN_SETS[1])
        data_file = IPSET_CONF
    else:
        fw = _rg_fw_state()
        nets = fw.get("networks") or {}
        total = len(nets.get("IPv4Subnets", [])) + len(nets.get("IPv6Subnets", []))
        data_file = RG_FIREWALL_CONF
    updated = ""
    try:
        ts = datetime.fromtimestamp(data_file.stat().st_mtime)
        updated = ts.strftime("%d.%m.%Y %H:%M")
    except Exception:
        pass
    return total, updated


def _rg_drop_counters() -> tuple[int, int]:
    """(pkts_v4, pkts_v6) дропов из счётчиков правил (без сброса)."""
    out4 = out6 = 0
    if _rg_backend() == "iptables":
        for binary, acc in (("iptables", "v4"), ("ip6tables", "v6")):
            r = _run([binary, "-w", "-L", _RGN_CHAIN, "-v", "-x", "-n"],
                     capture=True, timeout=10)
            for line in (r.stdout or "").splitlines():
                t = line.split()
                # "pkts bytes target prot opt …" — ищем правило с target DROP
                if len(t) >= 3 and t[2] == "DROP" and t[0].isdigit():
                    if acc == "v4":
                        out4 = int(t[0])
                    else:
                        out6 = int(t[0])
                    break
    else:
        r = _run(["nft", "list", "chain", _RGN_TABLE_NFT, "input"],
                 capture=True, timeout=10)
        for m in re.finditer(r"counter packets (\d+) bytes \d+.*drop",
                              r.stdout or ""):
            out4 += int(m.group(1))
    return out4, out6


def _rg_manual_count() -> int:
    try:
        return len([l for l in RG_MANUAL_FILE.read_text().splitlines() if l.strip()])
    except Exception:
        return 0


def _rg_exceptions_count() -> int:
    r = _rg_run(["exceptions", "list"], timeout=20)
    return len([l for l in (r.stdout or "").splitlines()
                if re.match(r"^\S+\s+(tcp|udp)\s+\d+", l)])


def _rg_panel_bound() -> bool:
    return RG_PANEL_DIR.exists() and any(RG_PANEL_DIR.iterdir())


def _rg_logging_active() -> tuple[bool, bool]:
    """(логирование правил настроено, rsyslog жив)."""
    fw = _rg_fw_state()
    on = bool(fw.get("logging", False)) if fw else False
    r = _run(["systemctl", "is-active", "--quiet", "rsyslog"], quiet=True)
    return on, r.returncode == 0


def _rg_schedule_show() -> str:
    """Человекочитаемое расписание + живость таймера."""
    mode, value = _rg_schedule_load()
    names = {
        "off":      "выключено",
        "interval": f"каждые {value} ч.",
        "hours":    f"ежедневно в {value} (МСК)",
        "msk":      "ежедневно в 06:00 (МСК)",
        "local":    "ежедневно в 06:00 (локальное время сервера)",
    }
    text = names.get(mode, "выключено")
    r = _run(["systemctl", "is-active", "--quiet", RG_TIMER], quiet=True)
    if mode != "off" and r.returncode == 0:
        r2 = _run(["systemctl", "is-enabled", "--quiet", RG_TIMER], quiet=True)
        text += " — активно" if r2.returncode == 0 else " — активно до перезагрузки"
    elif mode != "off":
        text += " — таймер не активен"
    return text


def _rg_schedule_load() -> tuple[str, str]:
    """Читает /etc/rkn-guard-update.conf → (mode, value)."""
    try:
        line = RG_SCHEDULE_CONF.read_text().strip()
        if "=" in line:
            mode, _, value = line.partition("=")
            return mode.strip(), value.strip()
    except Exception:
        pass
    return "off", ""


# ═════════════════════════════════════════════════════════════════════════════
#  /etc/ipset.conf — СЛИЯНИЕ-КОМПЕНСАЦИЯ (критичная интеграция, см. шапку)
# ═════════════════════════════════════════════════════════════════════════════
def _rg_line_is_rkn(line: str) -> bool:
    """Строка ipset-конфига принадлежит rkn-guard (сеты SCANNERS-BLOCK*/RKN-NEXT*)."""
    t = line.split()
    if len(t) >= 2 and t[0] in ("create", "add", "del", "flush", "swap", "rename"):
        tgt = t[1]
        return tgt in _RGN_SETS or tgt.startswith("RKN-NEXT")
    return False


def _rg_ipset_conf_snapshot() -> tuple[str, int]:
    """(содержимое, режим файла) ДО операции rkn-guard."""
    try:
        st = IPSET_CONF.stat()
        return IPSET_CONF.read_text(), st.st_mode & 0o777
    except FileNotFoundError:
        return "", 0o600
    except Exception:
        return "", 0o600


def _rg_ipset_conf_merge(before: str, mode: int = 0o600) -> None:
    """Сшивает /etc/ipset.conf ПОСЛЕ операции rkn-guard.

    rkn-guard перезаписывает файл ТОЛЬКО своими секциями SCANNERS-BLOCK-*
    (или удаляет его при uninstall) — чужие секции (Химера: xray_ru_block*,
    xray_manual_ban*, xray_knocked*, …) возвращаются дословно из снапшота
    before, секциями-по-сетам. Идемпотентно: секции, уже присутствующие в
    файле, не дублируются. Атомарная запись, режим сохраняется.
    """
    try:
        current = ""
        try:
            current = IPSET_CONF.read_text()
        except FileNotFoundError:
            pass
        except Exception:
            current = ""
        if current == before:
            return  # файл не тронут (nft-бэкенд / сбой до записи)

        def _set_of(line: str):
            t = line.split()
            if len(t) >= 2 and t[0] in ("create", "add", "del", "flush",
                                         "swap", "rename"):
                return t[1]
            return None

        current_sets = {s for s in (_set_of(l)
                                    for l in current.splitlines()) if s}
        # Секции снапшота (кроме rkn): имя сета → строки; None → преамбула
        foreign: dict = {}
        preamble: list[str] = []
        for l in before.splitlines():
            if _rg_line_is_rkn(l):
                continue
            s = _set_of(l)
            if s is None:
                if l.strip():
                    preamble.append(l)
                continue
            foreign.setdefault(s, []).append(l)

        current_line_set = set(current.splitlines())
        add_lines: list[str] = [l for l in preamble if l not in current_line_set]
        for s, ls in foreign.items():
            if s in current_sets:
                continue  # уже в файле — не дублируем (идемпотентность)
            add_lines += ls
        if not add_lines:
            return  # чужих секций нет / всё уже на месте

        parts = [l for l in current.splitlines()]
        if parts and parts[-1].strip():
            parts.append("")
        parts += add_lines
        merged = "\n".join(parts).strip("\n") + "\n"
        if merged == before:
            return
        IPSET_CONF.parent.mkdir(parents=True, exist_ok=True)
        tmp = IPSET_CONF.with_suffix(".ipset.new")
        tmp.write_text(merged)
        os.chmod(tmp, mode)
        os.replace(tmp, IPSET_CONF)
        rkn_n = len([l for l in merged.splitlines() if _rg_line_is_rkn(l)])
        _log("INFO", "/etc/ipset.conf: слияние после rkn-guard "
                     f"(своих секций {rkn_n}, чужих восстановлено {len(add_lines)})")
    except Exception as e:
        _warn(f"/etc/ipset.conf: не удалось выполнить слияние ({e}) — "
              f"проверьте секции вручную: {IPSET_CONF}")


def _rg_cli_mutate(args: list, timeout: int = 900,
                   label: str = "") -> subprocess.CompletedProcess:
    """Мутирующая операция rkn-guard: снапшот ipset.conf → CLI → слияние.

    Такими считаются full / update / uninstall / смена бэкенда — всё, что
    идёт через applySourceNetworks → Replace/Clear/удаление файла.
    """
    if label:
        _info(label)
    before, mode = _rg_ipset_conf_snapshot()
    r = _rg_run(args, timeout=timeout)
    _rg_ipset_conf_merge(before, mode)
    return r


# ═════════════════════════════════════════════════════════════════════════════
#  UFW-JUMP: АВТОРЕКОВЕРИ «SCANNERS-BLOCK is not the first rule»
#  (кейс <blw> 24.11: переустановка на ноде с внешним антидосом)
# ═════════════════════════════════════════════════════════════════════════════
#  Механика бага: бинарник после `ufw reload` верифицирует ЖИВУЮ цепочку
#  (verifyUFWJumps: первое -A-правило `iptables -S ufw-before-input` должно
#  быть ровно `-A ufw-before-input -j SCANNERS-BLOCK`). Managed-блок в
#  /etc/ufw/before.rules при этом корректен (insertUFWBlock всегда ставит
#  его перед первым правилом файла). Если внешняя система на ноде
#  (антидос/телеметрия хостера, длинный список drop-all, конкурирующая
#  вставка `iptables -I ufw-before-input …`) успевает положить своё правило
#  в начало живой цепочки между reload и verify — установка падает FTL,
#  хотя файл в порядке: «Не удалось сохранить правила iptables
#  error="ufw-before-input: SCANNERS-BLOCK is not the first rule"».
#
#  Рекавери: переставить jump на 1-е место ЖИВОЙ цепочки (v4+v6) и
#  повторить операцию ОДИН раз — файлы не изменились, поэтому бинарник
#  идёт по fast-path (без нового reload) и verify завершается успешно.
# ═════════════════════════════════════════════════════════════════════════════
_RG_UFW_CHAINS = (
    # (binary, ufw-цепочка) — как в verifyUFWJumps бинарника.
    ("iptables",  "ufw-before-input"),
    ("ip6tables", "ufw6-before-input"),
)
_RG_FIRST_RULE_ERR = "is not the first rule"


def _rg_ufw_first_rule(binary: str, chain: str) -> "str | None":
    """Первое -A-правило живой цепочки; None — цепочка не существует.

    Разбор как в verify бинарника: строки -N/-P пропускаются; '' — цепочка
    есть, но пуста.
    """
    r = _run([binary, "-w", "-S", chain], capture=True, timeout=15)
    if r.returncode != 0:
        return None
    for l in (r.stdout or "").splitlines():
        l = l.strip()
        if l.startswith("-A "):
            return l
    return ""


def _rg_ufw_jump_conflicts() -> list:
    """[(binary, chain, first)] — семейства, где jump стоит не первым.

    Отсутствующее семейство (нет ufw6-before-input на v6-off ноде)
    конфликтом НЕ считается.
    """
    out = []
    for binary, chain in _RG_UFW_CHAINS:
        first = _rg_ufw_first_rule(binary, chain)
        if first is None:
            continue
        if first != f"-A {chain} -j {_RGN_CHAIN}":
            out.append((binary, chain, first))
    return out


def _rg_repair_ufw_jump() -> bool:
    """Перестановка jump SCANNERS-BLOCK на 1-е место живой ufw-цепочки.

    Только существующие пары цепочек (ufw-before-* + SCANNERS-BLOCK): все
    вхождения jump удаляются (мог продублироваться), чистый jump
    вставляется `-I <chain> 1`; чужие правила не трогаются. Возвращает
    True, если после ремонта во всех существующих семействах jump первый
    (или конфликта не было).
    """
    for binary, chain in _RG_UFW_CHAINS:
        if _rg_ufw_first_rule(binary, chain) is None:
            continue  # семейства нет (v6-off) — не наша забота
        if _run([binary, "-w", "-S", _RGN_CHAIN], capture=True,
                timeout=10).returncode != 0:
            continue  # нашей цепочки нет — повтор full создаст её сам
        want = f"-A {chain} -j {_RGN_CHAIN}"
        if _rg_ufw_first_rule(binary, chain) == want:
            continue  # уже порядок
        for _ in range(20):  # снять ВСЕ вхождения jump (дубли)
            if _run([binary, "-w", "-D", chain, "-j", _RGN_CHAIN],
                    quiet=True).returncode != 0:
                break
        if _run([binary, "-w", "-I", chain, "1", "-j", _RGN_CHAIN],
                quiet=True).returncode != 0:
            _warn(f"{binary}: не удалось вставить jump в {chain}")
        else:
            _log("INFO", f"UFW jump repair: {binary} {chain} → позиция 1")
    conflicts = _rg_ufw_jump_conflicts()
    if conflicts:
        for binary, chain, first in conflicts:
            _log("WARN", f"UFW jump repair: {binary} {chain} всё ещё "
                         f"начинается с {first or '— (пусто)'}")
        return False
    return True


def _rg_cli_mutate_ufw_safe(args: list, timeout: int = 900,
                            label: str = "") -> subprocess.CompletedProcess:
    """Мутирующая операция + авторековери UFW-jump (кейс <blw> 24.11).

    При падении с «is not the first rule»: показать, что реально стоит
    первым в живых ufw-цепочках, переставить jump (см.
    _rg_repair_ufw_jump) и повторить операцию ОДИН раз — идемпотентно
    (full/update повторяемы, сеты меняются swap'ом, счётчики живы).
    """
    r = _rg_cli_mutate(args, timeout=timeout, label=label)
    combined = (r.stderr or "") + (r.stdout or "")
    if r.returncode == 0 or _RG_FIRST_RULE_ERR not in combined:
        return r
    _warn("UFW: verify бинарника упал — jump SCANNERS-BLOCK не первое "
          "правило живой ufw-before-input (чужие правила в начале цепочки: "
          "антидос/телеметрия). Чиню позицию и повторяю…")
    for binary, chain, first in _rg_ufw_jump_conflicts():
        _info(f"  {binary} -S {chain}: первым стоит "
              f"{first or '— (цепочка пуста)'}")
    if not _rg_repair_ufw_jump():
        _warn("Переставить jump не удалось — см. диагностику ниже")
        return r
    _info("Переставил jump на 1-е место; повторяю операцию rkn-guard…")
    r2 = _rg_cli_mutate(args, timeout=timeout)
    if r2.returncode == 0:
        _success("Повтор успешен: правила сохранены (fast-path, без "
                 "повторного ufw reload)")
    else:
        _warn("Повтор тоже не прошёл — на ноде постоянный конфликт за "
              "ufw-before-input (внешняя система перегенерирует правила "
              "или ruleset раздут). Диагностика: iptables -w -S "
              "ufw-before-input | head -5; iptables-save | grep -c "
              "'^-A' — всего правил (тысячи — мусор от сторонних "
              "пер-IP банов); grep -n SCANNERS-BLOCK /etc/ufw/before.rules "
              "| head -3")
    return r2


# ═════════════════════════════════════════════════════════════════════════════
#  BIN: СКАЧИВАНИЕ (зеркала), ВЕРСИЯ АПСТРИМА, СБОРКА ИЗ ИСТОЧНИКОВ
# ═════════════════════════════════════════════════════════════════════════════
def _rg_arch() -> str:
    m = {"x86_64": "amd64", "amd64": "amd64", "i386": "386", "i686": "386",
         "aarch64": "arm64", "arm64": "arm64", "armv7l": "arm", "armv6l": "arm"}
    return m.get(os.uname().machine, "")


def _rg_mirror_urls(filename: str) -> list[str]:
    """Зеркала бинарника релиза: release GitHub → gh-proxy×3."""
    urls = [f"https://github.com/{RG_UPSTREAM_REPO}/releases/latest/download/{filename}"]
    for host in ("ghproxy.net", "gh-proxy.com", "gh.llkk.cc"):
        urls.append(f"https://{host}/https://github.com/{RG_UPSTREAM_REPO}/"
                    f"releases/latest/download/{filename}")
    return urls


def _rg_download_binary() -> bool:
    """Ставит/обновляет бинарник через download_manager (зеркала + ручной /root)."""
    from chimera.modules.download_manager import PackageSpec, fetch_package
    arch = _rg_arch()
    if not arch:
        _err(f"Архитектура {os.uname().machine} не поддерживается rkn-guard")
        return False

    def _post_install(tmp_path: Path, _dests: list) -> bool:
        try:
            staged = RG_BIN.with_suffix(".new")
            shutil.copy2(tmp_path, staged)
            os.chmod(staged, 0o755)
            chk = _run([str(staged), "--version"], capture=True, timeout=30)
            if chk.returncode != 0:
                staged.unlink(missing_ok=True)
                _err("Новый бинарник не прошёл проверку --version — прежний сохранён")
                return False
            os.replace(staged, RG_BIN)
            return True
        except Exception as e:
            _log("ERR", f"post_install rkn-guard: {e}")
            return False

    spec = PackageSpec(
        name=f"rkn-guard binary (linux-{arch})",
        filename_builder=lambda **kw: f"rkn-guard-linux-{arch}",
        mirror_urls_builder=lambda filename, **kw: _rg_mirror_urls(filename),
        install_dests=[RG_BIN.parent],
        manual_incoming_dir=Path("/root"),
        min_size=1_000_000,
        post_install=_post_install,
    )
    return fetch_package(spec, progress_label="rkn-guard")


def _rg_latest_tag() -> str:
    """Тег последнего релиза с GitHub API (зеркала gh-proxy как fallback)."""
    import urllib.request
    urls = [RG_UPSTREAM_API] + [
        f"https://{h}/{RG_UPSTREAM_API}" for h in
        ("ghproxy.net", "gh-proxy.com", "gh.llkk.cc")
    ]
    for url in urls:
        try:
            req = urllib.request.Request(
                url, headers={"Accept": "application/vnd.github+json",
                              "User-Agent": "chimera-rkn-guard"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
                tag = str(data.get("tag_name", ""))
                if re.match(r"^v?[0-9]+\.[0-9]+\.[0-9]+$", tag):
                    return tag
        except Exception:
            continue
    return ""


def _rg_update_from_source(branch: str) -> bool:
    """Сборка из исходников ветки master/dev (go build) — как switch-branch.sh.

    Требует git + go ≥1.21 (toolchain докачивается автоматически при доступе
    в сеть). Правила firewall и счётчики НЕ сбрасываются (full не вызывается).
    """
    if not shutil.which("git"):
        _err("git не найден — сборка из исходников невозможна")
        return False
    go = shutil.which("go")
    if not go:
        _err("go не найден — установите golang-go (в зависимостях Chimera) "
             "или обновляйтесь бинарником из релизов")
        return False
    r = _run(["go", "version"], capture=True, timeout=15)
    m = re.search(r"go version go(\d+)\.(\d+)", r.stdout or "")
    if not m or (int(m.group(1)), int(m.group(2))) < (1, 21):
        _warn(f"go {(r.stdout or '').strip()!r} < 1.21 — toolchain должен "
              f"докачаться автоматически (нужен доступ к сети)")
    work = Path("/tmp/rkn-guard-src")
    _info(f"Клонирую исходники rkn-guard (ветка {branch})…")
    shutil.rmtree(work, ignore_errors=True)
    clone_urls = [f"https://github.com/{RG_UPSTREAM_REPO}.git"] + [
        f"https://{h}/https://github.com/{RG_UPSTREAM_REPO}.git" for h in
        ("ghproxy.net", "gh-proxy.com")
    ]
    cloned = False
    for cu in clone_urls:
        r = _run(["git", "clone", "--depth", "1", "-b", branch, cu, str(work)],
                 timeout=300)
        if r.returncode == 0:
            cloned = True
            break
        shutil.rmtree(work, ignore_errors=True)
    if not cloned:
        _err("Не удалось клонировать исходники (прямая ссылка + зеркала)")
        return False
    _info("Собираю (go build)…")
    r = _run(["go", "build", "-trimpath", "-ldflags",
              "-s -w", "-o", str(RG_BIN.with_suffix(".new")), "./cmd"],
             timeout=900, )
    if r.returncode != 0 or not RG_BIN.with_suffix(".new").exists():
        RG_BIN.with_suffix(".new").unlink(missing_ok=True)
        _err("go build не удался — бинарник не заменён")
        return False
    staged = RG_BIN.with_suffix(".new")
    os.chmod(staged, 0o755)
    chk = _run([str(staged), "--version"], capture=True, timeout=30)
    if chk.returncode != 0:
        staged.unlink(missing_ok=True)
        _err("Собранный бинарник не прошёл проверку — не заменяю")
        return False
    os.replace(staged, RG_BIN)
    _run([str(RG_BIN), "setup-logging"], timeout=120)
    shutil.rmtree(work, ignore_errors=True)
    _success(f"rkn-guard собран из ветки {branch} и установлен; "
             f"счётчики атак сохранены")
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / ПРЕДПОЛГОВКА
# ═════════════════════════════════════════════════════════════════════════════
def _rg_preflight_pkgs() -> bool:
    """rsyslog/logrotate/ipset (для логирования и iptables-бэкенда)."""
    missing = []
    for binary, pkg in (("rsyslogd", "rsyslog"), ("logrotate", "logrotate"),
                        ("ipset", "ipset"), ("iptables", "iptables")):
        if not shutil.which(binary):
            missing.append(pkg)
    if not missing:
        return True
    _info(f"Доставляю пакеты: {', '.join(missing)}…")
    if shutil.which("apt-get"):
        _run(["apt-get", "install", "-y", *missing], timeout=600)
    elif shutil.which("dnf"):
        _run(["dnf", "install", "-y", *missing], timeout=600)
    else:
        _err("нет apt-get/dnf — установите вручную: " + ", ".join(missing))
        return False
    ok = all(shutil.which(b) for b, _ in
             (("rsyslogd",), ("logrotate",), ("ipset",), ("iptables",)))
    return ok


def _rg_install_flow(st: dict, interactive: bool = True) -> bool:
    """Полная установка rkn-guard (бинарник → full → setup-logging → таймер).

    interactive=False — использовать st как есть (переустановка/CLI).
    """
    if os.geteuid() != 0:
        _err("требуются права root")
        return False
    if not _rg_preflight_pkgs():
        return False
    if not _rg_installed():
        _info("Скачиваю бинарник rkn-guard (зеркала: release GitHub → gh-proxy)…")
        if not _rg_download_binary():
            _err("Бинарник не установлен — положите rkn-guard-linux-"
                 f"{_rg_arch() or 'amd64'} в /root и повторите (WinSCP)")
            return False
        _success(f"Бинарник установлен: {RG_BIN}")

    backend = st.get("firewall", "iptables")
    logging_on = bool(st.get("logging", True))
    urls = _rg_base_urls(st)

    r = _rg_run(["firewall-select", backend], timeout=60)
    if r.returncode != 0:
        _err("firewall-select не прошёл:\n" + (r.stderr or r.stdout or "")[:400])
        return False

    args = ["full"]
    for u in urls:
        args += ["--urls", u]
    args += ["--firewall", backend, "--managed-lists",
             "--sources-file", str(RG_SOURCES_FILE)]
    if logging_on:
        args += ["--enable-logging"]

    r = _rg_cli_mutate_ufw_safe(
        args, timeout=900,
        label=f"Применяю списки и правила ({backend}, "
              f"{len(urls)} базовых источника)…")
    if r.returncode != 0:
        tail = "\n".join(((r.stderr or "") + (r.stdout or "")).splitlines()[-12:])
        _err("rkn-guard full не завершился:\n" + tail)
        if _RG_FIRST_RULE_ERR in (r.stderr or "") + (r.stdout or ""):
            _err("UFW-конфликт не разрешился автоматически. Проверьте, кто "
                 "держит правила в начале ufw-before-input (антидос/"
                 "телеметрия хостера) и не раздут ли ruleset:\n"
                 "  iptables -w -S ufw-before-input | head -5\n"
                 "  iptables-save | grep -c '^-A'   # всего правил; "
                 "десятки тысяч — мусор от пер-IP банов\n"
                 "  grep -n SCANNERS-BLOCK /etc/ufw/before.rules | head -3")
        return False

    if logging_on:
        r = _rg_run(["setup-logging"], timeout=300)
        if r.returncode != 0:
            _warn("setup-logging не удался (статистика недоступна, защита работает):\n"
                  + ((r.stderr or r.stdout or "")[:300]))
        else:
            _run(["systemctl", "enable", "--now", "rsyslog"], quiet=True)

    st["enabled"] = True
    st["installed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ver, branch = _rg_version()
    st["version"], st["branch"] = ver, branch
    _rg_state_save(st)

    mode, value = st.get("schedule_mode", "off"), st.get("schedule_value", "")
    if mode != "off":
        _rg_schedule_set(mode, value)

    _success("rkn-guard установлен и активен")
    _tg_notify_event("rkn_guard_install",
                     f"backend={backend}, списков={len(urls)}, лог={logging_on}")
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ СПИСКОВ
# ═════════════════════════════════════════════════════════════════════════════
def _rg_update_now(interactive: bool = True) -> int:
    """Обновление списков сейчас (без сброса счётчиков). rc=2 — частичное."""
    if not _rg_installed():
        _err("rkn-guard не установлен")
        return 1
    st = _rg_state_load()
    urls = _rg_base_urls(st)
    args = ["update", "--managed-lists", "--sources-file", str(RG_SOURCES_FILE)]
    for u in urls:
        args += ["--urls", u]
    r = _rg_cli_mutate_ufw_safe(
        args, timeout=900,
        label="Обновляю списки подсетей (счётчики атак сохраняются)…")
    if r.returncode == 2:
        _warn("Обновление завершено с ошибками части источников — для них "
              "взяты последние корректные копии из кэша")
        st["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _rg_state_save(st)
        return 2
    if r.returncode != 0:
        tail = "\n".join(((r.stderr or "") + (r.stdout or "")).splitlines()[-8:])
        _err("Обновление не выполнено:\n" + tail)
        return 1
    st["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _rg_state_save(st)
    total, _upd = _rg_subnets_total()
    _success(f"Списки обновлены: {total} подсетей активно")
    return 0


def rkn_cli_update() -> int:
    """CLI-вход для таймера: main.py --rkn-update (root).

    update --managed-lists + ОБЯЗАТЕЛЬНОЕ слияние /etc/ipset.conf (иначе
    ежедневный rkn-guard update затирает секции Химеры).
    """
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        return 1
    if not _rg_installed():
        print("rkn-guard не установлен — таймеру нечего обновлять",
              file=sys.stderr)
        return 0
    rc = _rg_update_now(interactive=False)
    print(f"rkn-guard update rc={rc}")
    return rc


# ═════════════════════════════════════════════════════════════════════════════
#  РАСПИСАНИЕ (режимы как в апстриме; юниты — НАШИ, с merge-компенсацией)
# ═════════════════════════════════════════════════════════════════════════════
def _rg_main_py() -> Path:
    """Путь к main.py — надёжно (argv[0] может быть '-' при stdin-запуске)."""
    try:
        cand = Path(sys.argv[0]).resolve()
        if cand.name == "main.py" and cand.exists():
            return cand
    except Exception:
        pass
    # __file__ = <root>/chimera/modules/rkn_guard.py → root
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "main.py"
        if cand.exists():
            return cand
    return Path("/opt/chimera/main.py")


def _rg_schedule_normalize(mode: str, value: str) -> str:
    """Валидация и нормализация расписания; бросает ValueError."""
    mode = (mode or "").strip().lower()
    value = (value or "").strip()
    if mode == "off":
        return ""
    if mode == "interval":
        if not re.match(r"^[0-9]{1,3}$", value):
            raise ValueError("интервал — целое число часов")
        n = int(value)
        if not (1 <= n <= 168):
            raise ValueError("интервал 1–168 ч.")
        return str(n)
    if mode == "msk":
        return "06:00"
    if mode == "local":
        return "06:00"
    if mode == "hours":
        if len(value) > 256 or not re.match(r"^[0-9:, \t]+$", value):
            raise ValueError("времена: 0–23 или ЧЧ:ММ через запятую")
        value = re.sub(r"[ \t]", "", value)
        if not value or value.startswith(",") or value.endswith(",") or ",," in value:
            raise ValueError("пустой элемент в списке времён")
        times = value.split(",")
        if len(times) > 24:
            raise ValueError("не больше 24 значений")
        out = set()
        for t in times:
            m = re.match(r"^(\d{1,2})(?::(\d{2}))?$", t)
            if not m:
                raise ValueError(f"неверное время: {t!r}")
            h, mm = int(m.group(1)), int(m.group(2) or 0)
            if h > 23 or mm > 59:
                raise ValueError(f"время вне диапазона: {t!r}")
            out.add(f"{h:02d}:{mm:02d}")
        return ",".join(sorted(out))
    raise ValueError(f"неизвестный режим: {mode}")


def _rg_schedule_set(mode: str, value: str = "") -> bool:
    """Записывает расписание: наш service+timer (ExecStart → main.py
    --rkn-update, со слиянием ipset.conf) + конфиг апстрим-формата."""
    try:
        value = _rg_schedule_normalize(mode, value)
    except ValueError as e:
        _err(f"Неверное расписание: {e}")
        return False
    mode = (mode or "").strip().lower()
    st = _rg_state_load()
    st["schedule_mode"] = mode
    st["schedule_value"] = value
    _rg_state_save(st)

    # Снимаем действующий таймер (не прерывая уже идущее обновление)
    _run(["systemctl", "disable", "--now", RG_TIMER], quiet=True)

    if mode == "off":
        for f in (RG_TIMER_PATH, RG_SERVICE_PATH):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            RG_SCHEDULE_CONF.unlink(missing_ok=True)
        except Exception:
            pass
        _run(["systemctl", "daemon-reload"], quiet=True)
        _success("Автообновление списков отключено")
        return True

    script_path = _rg_main_py()
    RG_SERVICE_PATH.write_text(f"""[Unit]
Description=rkn-guard — обновление списков подсетей (Chimera)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart={sys.executable} {script_path} --rkn-update
StandardInput=null
StandardOutput=journal
StandardError=journal
""")
    cal = ""
    if mode == "interval":
        cal = f"OnActiveSec={value}h\nOnUnitActiveSec={value}h\n"
    else:
        times = value.split(",") if mode == "hours" else ["06:00"]
        for t in times:
            if mode == "local":
                cal += f"OnCalendar=*-*-* {t}:00\n"
            else:
                cal += f"OnCalendar=*-*-* {t}:00 Europe/Moscow\n"
        cal += "Persistent=true\n"
    RG_TIMER_PATH.write_text(f"""[Unit]
Description=rkn-guard — расписание обновления подсетей

[Timer]
{cal}AccuracySec=1s
Unit={RG_SERVICE}

[Install]
WantedBy=timers.target
""")
    try:
        RG_SCHEDULE_CONF.write_text(f"{mode}={value}\n")
    except Exception:
        pass
    _run(["systemctl", "daemon-reload"], quiet=True)
    if _run(["systemctl", "enable", "--now", RG_TIMER]).returncode == 0:
        _success(f"Автообновление: {_rg_schedule_show()}")
        return True
    _err("Не удалось включить таймер — см. systemctl status " + RG_TIMER)
    return False


# ═════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ / ПЕРЕУСТАНОВКА
# ═════════════════════════════════════════════════════════════════════════════
def _rg_uninstall_flow(remove_logs: bool, interactive: bool = True) -> bool:
    """uninstall rkn-guard (правила/сервисы/конфиги) + возврат чужих секций
    /etc/ipset.conf + чистка нашего state/таймера."""
    if not _rg_installed():
        _err("rkn-guard не установлен")
        return False
    if interactive and not _confirm(
            "Снять защиту и удалить rkn-guard"
            + (" вместе с журналами и статистикой" if remove_logs else "")
            + "?", default_yes=False):
        return False
    args = ["uninstall", "--yes"]
    if remove_logs:
        args += ["--remove-logs"]
    r = _rg_cli_mutate(args, timeout=600, label="Демонтирую правила и сервисы…")
    if r.returncode != 0:
        tail = "\n".join(((r.stderr or "") + (r.stdout or "")).splitlines()[-10:])
        _err("uninstall не завершился:\n" + tail)
        return False
    # Наш таймер/state
    _run(["systemctl", "disable", "--now", RG_TIMER], quiet=True)
    for f in (RG_TIMER_PATH, RG_SERVICE_PATH):
        try:
            f.unlink(missing_ok=True)
        except Exception:
            pass
    try:
        RG_SCHEDULE_CONF.unlink(missing_ok=True)
    except Exception:
        pass
    _run(["systemctl", "daemon-reload"], quiet=True)
    st = _rg_state_load()
    st["enabled"] = False
    st["schedule_mode"] = "off"
    st["schedule_value"] = ""
    _rg_state_save(st)
    _success("rkn-guard удалён; химерные секции /etc/ipset.conf восстановлены")
    _tg_notify_event("rkn_guard_uninstall",
                     "logs removed" if remove_logs else "logs kept")
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: СПИСКИ (базовые + дополнительные источники)
# ═════════════════════════════════════════════════════════════════════════════
def _rg_base_args() -> list[str]:
    args: list[str] = []
    for u in _rg_base_urls():
        args += ["--base-url", u]
    return args


def _rg_menu_lists() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    while True:
        os.system("clear")
        st = _rg_state_load()
        src = _rg_sources_state()
        print()
        _box_top("📋  RKN-GUARD  •  УПРАВЛЕНИЕ СПИСКАМИ ПОДСЕТЕЙ")
        _box_row(f"  {DIM}Базовые источники определяют состав защиты; доп. — "
                 f"ваши списки CIDR по URL.{NC}")
        _box_sep()
        idx = 0
        for e in st.get("base_urls", []):
            idx += 1
            try:
                un = _rg_norm_url(e["url"])
            except Exception:
                un = e["url"]
            enabled = _rg_base_enabled(un, src)
            cache = (src.get("cache") or {}).get(un, {})
            n_nets = len(cache.get("networks", []))
            upd = (cache.get("updated_at", "") or "")[:16].replace("T", " ")
            err = cache.get("last_error", "")
            mark = f"{GREEN}вкл{NC}" if enabled else f"{RED}выкл{NC}"
            label = e.get("label", un.split("/")[-1])
            _box_row(f"  {idx}. [{mark}] {label}{NC}")
            _box_row(f"     {DIM}{un}{NC}")
            stat = f"подсетей в кэше: {CYAN}{n_nets}{NC}"
            if upd:
                stat += f" · {DIM}обновлён {upd}{NC}"
            if err:
                stat += f"\n     {YELLOW}ошибка: {err[:60]}{NC}"
            _box_row(f"     {stat}")
        _box_sep()
        extra = src.get("extra", [])
        _box_row(f"  Доп. источники: {CYAN}{len(extra)}{NC} "
                 f"{DIM}(списки CIDR по вашему URL){NC}")
        _box_sep()
        _box_item("1", "Включить/отключить базовый список")
        _box_item("2", "Полностью заменить набор базовых URL")
        _box_item("3", "Доп. источники: добавить / вкл / выкл / удалить")
        _box_item("U", "Обновить списки сейчас (применить изменения)")
        _box_back()
        _box_bottom()
        ch = _input(f"{CYAN}Выбор: {NC}").lower()
        if ch in ("q", ""):
            return
        elif ch == "1":
            n = _input("Номер базового списка: ")
            if not re.match(r"^[1-9][0-9]*$", n or ""):
                _warn("Введите номер из списка")
                time.sleep(1)
                continue
            n = int(n)
            urls = _rg_base_urls(st)
            if not (1 <= n <= len(urls)):
                _warn(f"Номер 1–{len(urls)}")
                time.sleep(1)
                continue
            un = urls[n - 1]
            enabled = _rg_base_enabled(un, src)
            action = "base-disable" if enabled else "base-enable"
            r = _rg_run(["sources", action, str(n), *_rg_base_args()], timeout=60)
            if r.returncode != 0:
                _err("sources " + action + ":\n" + (r.stderr or "")[:300])
                time.sleep(1)
                continue
            _rg_update_now()
            time.sleep(1)
        elif ch == "2":
            print(f"{DIM}Вводите URL по одному, Enter на пустой строке — "
                  f"завершить (пустой ввод — отмена):{NC}")
            urls: list[str] = []
            while len(urls) < 32:
                u = _input(f"  URL [{len(urls) + 1}]: ")
                if u == "":
                    break
                try:
                    un = _rg_norm_url(u)
                    if un not in urls:
                        urls.append(un)
                except ValueError as e:
                    _warn(f"Пропущен ({e})")
            if not urls:
                _warn("Набор не изменён (пусто)")
                time.sleep(1)
                continue
            st["base_urls"] = [{"key": f"src{i+1}", "label": u.split("/")[-1],
                                "url": u} for i, u in enumerate(urls)]
            _rg_state_save(st)
            _success(f"Набор базовых URL: {len(urls)} шт. — примените обновление")
            time.sleep(1)
        elif ch == "3":
            _rg_menu_extra_sources()
        elif ch == "u":
            _rg_update_now()
            time.sleep(1)


def _rg_menu_extra_sources() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    while True:
        os.system("clear")
        src = _rg_sources_state()
        extra = src.get("extra", [])
        print()
        _box_top("🧩  RKN-GUARD  •  ДОПОЛНИТЕЛЬНЫЕ ИСТОЧНИКИ")
        if not extra:
            _box_row(f"  {DIM}Доп. источников нет — добавьте URL текстового "
                     f"списка CIDR{NC}")
        for e in extra:
            mark = f"{GREEN}вкл{NC}" if e.get("enabled") else f"{RED}выкл{NC}"
            cache = (src.get("cache") or {}).get(e.get("url"), {})
            _box_row(f"  {e.get('id')}. [{mark}] {e.get('url')}")
            _box_row(f"     {DIM}подсетей: {len(cache.get('networks', []))}"
                     f" · обновлён {(cache.get('updated_at','') or '')[:16].replace('T',' ')}{NC}")
        _box_sep()
        _box_item("A", "Добавить источник (URL)")
        _box_item("E", "Включить по номеру/URL")
        _box_item("D", "Отключить по номеру/URL")
        _box_item("R", "Удалить по номеру/URL")
        _box_item("U", "Обновить списки сейчас")
        _box_back()
        _box_bottom()
        ch = _input(f"{CYAN}Выбор: {NC}").lower()
        if ch in ("q", ""):
            return
        if ch == "a":
            u = _input("URL текстового списка CIDR: ")
            if not u:
                continue
            r = _rg_run(["sources", "add", u, *_rg_base_args()], timeout=120)
            if r.returncode != 0:
                _err("Не добавлен:\n" + (r.stderr or "")[:300])
            else:
                _success("Источник проверен и добавлен (выключен — включите и обновите)")
        elif ch in ("e", "d", "r"):
            act = {"e": "enable", "d": "disable", "r": "remove"}[ch]
            sel = _input("Номер или URL источника: ")
            if not sel:
                continue
            r = _rg_run(["sources", act, sel, *_rg_base_args()], timeout=60)
            if r.returncode != 0:
                _err("sources " + act + ":\n" + (r.stderr or "")[:300])
            else:
                _rg_update_now()
        elif ch == "u":
            _rg_update_now()
            time.sleep(1)


# ═════════════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: РУЧНЫЕ БАНЫ / ИСКЛЮЧЕНИЯ
# ═════════════════════════════════════════════════════════════════════════════
def _rg_menu_manual() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    while True:
        os.system("clear")
        print()
        _box_top("🚫  RKN-GUARD  •  РУЧНЫЕ БАНЫ IP")
        r = _rg_run(["manual-ips", "list"], timeout=30)
        lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
        if lines:
            for l in lines[:40]:
                _box_row(f"  • {CYAN}{l}{NC}")
            if len(lines) > 40:
                _box_row(f"  {DIM}… и ещё {len(lines) - 40}{NC}")
        else:
            _box_row(f"  {DIM}Ручных банов нет{NC}")
        _box_sep()
        _box_row(f"  {DIM}Бан применяется мгновенно (сет SCANNERS-BLOCK); "
                 f"исключения из подсетей — отдельно (меню «Исключения»).{NC}")
        _box_sep()
        _box_item("A", "Забанить IP")
        _box_item("D", "Разбанить IP")
        _box_back()
        _box_bottom()
        ch = _input(f"{CYAN}Выбор: {NC}").lower()
        if ch in ("q", ""):
            return
        if ch == "a":
            ip = _input("IP для бана: ")
            if not ip:
                continue
            r = _rg_run(["manual-ips", "add", ip], timeout=60)
            if r.returncode == 0:
                _success((r.stdout or "").strip() or "Забанен")
            else:
                _err((r.stderr or "")[:200])
            time.sleep(1)
        elif ch == "d":
            ip = _input("IP для разбана: ")
            if not ip:
                continue
            r = _rg_run(["manual-ips", "delete", ip], timeout=60)
            if r.returncode == 0:
                _success((r.stdout or "").strip() or "Разбанен")
            else:
                _err((r.stderr or "")[:200])
            time.sleep(1)


def _rg_menu_exceptions() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    while True:
        os.system("clear")
        print()
        _box_top("✅  RKN-GUARD  •  ИСКЛЮЧЕНИЯ (проход мимо блоков)")
        r = _rg_run(["exceptions", "list"], timeout=30)
        lines = [l for l in (r.stdout or "").splitlines()
                 if re.match(r"^\S+\s+(tcp|udp)\s+\d+", l)]
        if lines:
            for l in lines[:40]:
                _box_row(f"  • {CYAN}{l}{NC}")
        else:
            _box_row(f"  {DIM}Исключений нет{NC}")
        _box_sep()
        _box_row(f"  {DIM}IP источника + протокол + порт назначения: "
                 f"соединение пройдет ДО/lists-блоков; остальные правила "
                 f"фаервола продолжают действовать.{NC}")
        _box_sep()
        _box_item("A", "Добавить исключение")
        _box_item("D", "Удалить исключение")
        _box_back()
        _box_bottom()
        ch = _input(f"{CYAN}Выбор: {NC}").lower()
        if ch in ("q", ""):
            return
        if ch == "a":
            ip = _input("IP источника: ")
            proto = _input("Протокол (tcp/udp): ", "tcp").lower()
            port = _input("Порт назначения: ")
            if not (ip and proto in ("tcp", "udp") and port.isdigit()):
                _warn("Нужно: IP, tcp|udp, порт")
                time.sleep(1)
                continue
            r = _rg_run(["exceptions", "add", ip, proto, port], timeout=60)
            if r.returncode == 0:
                _success((r.stdout or "").strip() or "Исключение применено")
            else:
                _err((r.stderr or "")[:200])
            time.sleep(1)
        elif ch == "d":
            ip = _input("IP источника: ")
            proto = _input("Протокол (tcp/udp): ", "tcp").lower()
            port = _input("Порт назначения: ")
            if not (ip and port):
                continue
            r = _rg_run(["exceptions", "delete", ip, proto, port], timeout=60)
            if r.returncode == 0:
                _success((r.stdout or "").strip() or "Исключение удалено")
            else:
                _err((r.stderr or "")[:200])
            time.sleep(1)


# ═════════════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: СТАТИСТИКА И ЖУРНАЛЫ
# ═════════════════════════════════════════════════════════════════════════════
def _rg_menu_stats() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    while True:
        os.system("clear")
        pkts4, pkts6 = _rg_drop_counters()
        print()
        _box_top("📊  RKN-GUARD  •  СТАТИСТИКА И ЖУРНАЛЫ")
        _box_row(f"  Дропов всего: {CYAN}{pkts4}{NC} (IPv4) · {CYAN}{pkts6}{NC} (IPv6)")
        for f, name in ((RG_LOG_V4, "IPv4"), (RG_LOG_V6, "IPv6")):
            try:
                st = f.stat()
                _box_row(f"  Журнал {name}: {DIM}{f}{NC}")
                _box_row(f"     {DIM}{st.st_size // 1024} КБ · изменён "
                         f"{datetime.fromtimestamp(st.st_mtime).strftime('%d.%m %H:%M')}{NC}")
            except OSError:
                _box_row(f"  Журнал {name}: {DIM}нет{NC}")
        try:
            st = RG_AGGREGATE_CSV.stat()
            _box_row(f"  Агрегат (ASN/netname): {DIM}{st.st_size // 1024} КБ · "
                     f"{datetime.fromtimestamp(st.st_mtime).strftime('%d.%m %H:%M')}{NC}")
        except OSError:
            pass
        _box_sep()
        _box_item("S", "Топ атакующих (агрегированная статистика)")
        _box_item("4", "Последние события IPv4")
        _box_item("6", "Последние события IPv6")
        _box_item("L", "Восстановить сбор статистики (setup-logging)")
        _box_back()
        _box_bottom()
        ch = _input(f"{CYAN}Выбор: {NC}").lower()
        if ch in ("q", ""):
            return
        if ch == "s":
            _info("Обновляю статистику (rkn-guard stats)…")
            r = _rg_run(["stats"], timeout=120)
            print()
            if r.returncode == 0:
                print(r.stdout or "")
            else:
                _err("Статистика не собралась:\n" + (r.stderr or "")[:400])
            input(f"{BLUE}Нажмите Enter…{NC}")
        elif ch in ("4", "6"):
            path = RG_LOG_V4 if ch == "4" else RG_LOG_V6
            print()
            _info(f"Последние события ({path}):")
            try:
                lines = path.read_text(errors="replace").splitlines()[-30:]
                for l in lines:
                    print(f"  {DIM}{l}{NC}")
                if not lines:
                    _warn("Журнал пуст — дропов с логированием ещё не было")
            except OSError:
                _warn("Журнал отсутствует")
            input(f"{BLUE}Нажмите Enter…{NC}")
        elif ch == "l":
            r = _rg_run(["setup-logging"], timeout=300)
            if r.returncode == 0:
                _success("Сбор статистики восстановлен (rsyslog + aggregate 30с)")
            else:
                _err("setup-logging:\n" + (r.stderr or "")[:300])
            time.sleep(1)


# ═════════════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: FIREWALL-БЭКЕНД
# ═════════════════════════════════════════════════════════════════════════════
def _rg_menu_firewall() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    while True:
        os.system("clear")
        fw = _rg_fw_state()
        backend = str(fw.get("backend", "iptables"))
        label = _FIREWALL_LABELS.get(backend, backend)
        if backend == "iptables" and shutil.which("ufw"):
            r = _run(["ufw", "status"], capture=True, timeout=15)
            if "Status: active" in (r.stdout or ""):
                label = "UFW (iptables + ipset)"
        print()
        _box_top("🔥  RKN-GUARD  •  FIREWALL-БЭКЕНД")
        _box_row(f"  Текущий:     {CYAN}{label}{NC}")
        total, upd = _rg_subnets_total()
        _box_row(f"  Подсетей:    {CYAN}{total}{NC} {DIM}(обновлены {upd} МСК){NC}")
        _box_sep()
        _box_row(f"  {DIM}Смена бэкенда = переустановка правил (списки/баны/{NC}")
        _box_row(f"  {DIM}исключения и счётчики дропов сбрасываются). Дефолт "
                 f"Химеры —{NC}")
        _box_row(f"  {DIM}iptables+ipset: единый стек с ingress_geoip/ipban/"
                 f"port_knocking.{NC}")
        _box_sep()
        _box_item("1", "iptables + ipset (вкл. UFW) — дефолт Химеры")
        _box_item("2", "nftables (отдельная таблица inet rkn_guard)")
        _box_item("3", "firewalld (бэкенд nftables)")
        _box_item("4", "auto — автоопределение (чистый сервер → nftables)")
        _box_item("S", "Статус правил (цепочка/таблица, сеты, jump в UFW)")
        _box_back()
        _box_bottom()
        ch = _input(f"{CYAN}Выбор: {NC}").lower()
        if ch in ("q", ""):
            return
        if ch == "s":
            _info("Живые правила:")
            if _rg_backend() == "iptables":
                r = _run(["iptables", "-w", "-S", _RGN_CHAIN], capture=True)
                print(r.stdout or "  (цепочки нет)")
                r = _run(["iptables", "-w", "-S", "ufw-before-input"], capture=True)
                for l in (r.stdout or "").splitlines():
                    if _RGN_CHAIN in l:
                        print(f"  {CYAN}{l}{NC}")
                r = _run(["ipset", "list", _RGN_SETS[0]], capture=True)
                m = re.search(r"Number of entries:\s*(\d+)", r.stdout or "")
                print(f"  set {_RGN_SETS[0]}: {m.group(1) if m else '?'} подсетей")
            else:
                r = _run(["nft", "list", "table", _RGN_TABLE_NFT], capture=True)
                print(r.stdout or "  (таблицы нет)")
            input(f"{BLUE}Нажмите Enter…{NC}")
            continue
        if ch not in ("1", "2", "3", "4"):
            continue
        mode = {"1": "iptables", "2": "nftables", "3": "firewalld",
                "4": "auto"}[ch]
        if mode == "auto":
            r = _rg_run(["firewall-select", "auto"], timeout=60)
            mode = (r.stdout or "").strip().splitlines()[0] if r.returncode == 0 else ""
            if not mode:
                _err("автоопределение не удалось:\n" + (r.stderr or "")[:300])
                continue
            _info(f"Автоопределение выбрало: {mode}")
            if mode != "iptables":
                _warn("на Химере рекомендован iptables+ipset (единый стек) — "
                      "продолжаю по вашему выбору")
        if mode != "iptables":
            _warn("Смена на nftables/firewalld: /etc/ipset.conf и UFW-"
                  "интеграция больше не используются; химерные правила не "
                  "затрагиваются (отдельная таблица)")
        if not _confirm(f"Переустановить rkn-guard на бэкенд «{mode}»?", False):
            continue
        st = _rg_state_load()
        st["firewall"] = mode
        _rg_uninstall_flow(remove_logs=False, interactive=False)
        _rg_install_flow(st, interactive=False)
        input(f"{BLUE}Нажмите Enter…{NC}")
        return


# ═════════════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: ПАНЕЛЬ rkn-guard-panel (Windows)
# ═════════════════════════════════════════════════════════════════════════════
def _rg_menu_panel() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    while True:
        os.system("clear")
        bound = _rg_panel_bound()
        print()
        _box_top("🖥️  RKN-GUARD  •  ПАНЕЛЬ rkn-guard-panel (Windows)")
        if bound:
            _box_row(f"  Привязка: {GREEN}создана{NC}")
        else:
            _box_row(f"  Привязка: {DIM}не создана{NC}")
        _box_sep()
        _box_row(f"  {DIM}Панель (Windows) показывает нагрузку, дропы и историю;{NC}")
        _box_row(f"  {DIM}меняет баны/исключения/списки/расписание, обновляет и{NC}")
        _box_row(f"  {DIM}переустанавливает rkn-guard по SSH (служебный юзер{NC}")
        _box_row(f"  {DIM}rkn-guard-user, свой ключ, sudo-правило — без открытия{NC}")
        _box_row(f"  {DIM}нового порта).{NC}")
        _box_row(f"  {DIM}Скачать: {RG_PANEL_APP_URL}{NC}")
        _box_sep()
        if bound:
            _box_item("R", "Отозвать привязку (пользователь + ключи)")
        else:
            _box_item("I", "Подключить панель (код RKN1, действует 5 минут)")
        _box_back()
        _box_bottom()
        ch = _input(f"{CYAN}Выбор: {NC}").lower()
        if ch in ("q", ""):
            return

        if ch == "r" and bound:
            if _confirm("Отозвать доступ панели и удалить rkn-guard-user?", False):
                r = _rg_run(["panel", "revoke"], timeout=60)
                if r.returncode == 0:
                    _success("Привязка отозвана")
                else:
                    _err((r.stderr or "")[:300])
            time.sleep(1)
            continue

        if ch == "i" and not bound:
            # Требования панели: python3 ≥3.8, авторизационные ключи, sshd
            if not shutil.which("python3"):
                _err("python3 не найден — панели требуется 3.8+")
                time.sleep(1)
                continue
            # Адрес/порт SSH: из текущего сеанса (SSH_CONNECTION), иначе —
            # исходящий адрес + порт sshd (как в апстрим-меню)
            host = port = ""
            conn = os.environ.get("SSH_CONNECTION", "").split()
            if len(conn) == 4:
                host, port = conn[2], conn[3]
            if not host or not port.isdigit():
                r = _run(["ip", "-4", "route", "get", "192.0.2.1"], capture=True)
                m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", r.stdout or "")
                host = m.group(1) if m else ""
                r = _run(["sshd", "-T"], capture=True, timeout=15)
                m = re.search(r"^port (\d+)", r.stdout or "", re.M)
                port = m.group(1) if m else ""
            if not host or not port.isdigit():
                host = _input("Внешний адрес сервера для панели: ")
                port = _input("Порт SSH: ", "22")
            if not host or not port.isdigit():
                _warn("Не определён адрес/порт SSH — привязка отменена")
                time.sleep(1)
                continue
            _info(f"SSH для панели: {host} (порт {port})")
            if not _confirm("Разрешить привязку панели?", False):
                continue
            print()
            r = _rg_run(["panel", "issue", host, port], timeout=120)
            if r.returncode != 0:
                _err("panel issue:\n" + (r.stderr or "")[:400])
                time.sleep(1)
                continue
            print()
            print(f"{CYAN}{'═' * 62}{NC}")
            print(f"{BOLD}  Скопируйте строку RKN1… в панель rkn-guard-panel{NC}")
            print(f"{BOLD}  (кнопка «Добавить по коду»), задайте имя сервера.{NC}")
            print(f"{CYAN}{'═' * 62}{NC}")
            print(r.stdout or "")
            print(f"{DIM}  Код действует 5 минут и гасится при первом обмене; "
                  f"храните его в секрете.{NC}")
            print(f"{CYAN}{'═' * 62}{NC}")
            input(f"{BLUE}Нажмите Enter…{NC}")


def _rg_menu_update_binary() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    os.system("clear")
    ver, branch = _rg_version()
    print()
    _box_top("⬆️  RKN-GUARD  •  ОБНОВЛЕНИЕ С АПСТРИМА")
    _box_row(f"  Установлено:  {CYAN}{ver or '?'}{NC} {DIM}(ветка {branch or '?'}){NC}")
    latest = _rg_latest_tag()
    if latest:
        _box_row(f"  Апстрим:      {CYAN}{latest}{NC}")
        if ver and latest.lstrip("v") == ver.lstrip("v"):
            _box_row(f"  {GREEN}Версия актуальна — обновление не требуется{NC}")
        else:
            _box_row(f"  {YELLOW}Есть новая версия{NC}")
    else:
        _box_row(f"  Апстрим:      {DIM}не удалось узнать (GitHub API/зеркала молчат){NC}")
    _box_sep()
    _box_item("U", "Обновить бинарник из релиза (счётчики сохраняются)")
    _box_item("B", "Собрать из исходников (ветка master/dev, git+go)")
    _box_back()
    _box_bottom()
    ch = _input(f"{CYAN}Выбор: {NC}").lower()
    if ch in ("q", ""):
        return
    if ch == "u":
        if latest and ver and latest.lstrip("v") == ver.lstrip("v") \
                and not _confirm("Версии совпадают — перекачать всё равно?", False):
            return
        if _rg_download_binary():
            r = _rg_run(["setup-logging"], timeout=300)
            if r.returncode == 0:
                _success("Сборщик статистики обновлён; счётчики атак сохранены")
            else:
                _warn("setup-logging после обновления не удался (не критично)")
            st = _rg_state_load()
            st["version"], st["branch"] = _rg_version()
            _rg_state_save(st)
        input(f"{BLUE}Нажмите Enter…{NC}")
    elif ch == "b":
        branch = _input("Ветка [master]: ", "master") or "master"
        if branch not in ("master", "dev"):
            _warn("Ветка должна быть master или dev")
            time.sleep(1)
            return
        _rg_update_from_source(branch)
        st = _rg_state_load()
        st["version"], st["branch"] = _rg_version()
        _rg_state_save(st)
        input(f"{BLUE}Нажмите Enter…{NC}")


def _rg_menu_schedule() -> None:
    from chimera.modules.box_renderer import _box_top, _box_row, _box_sep, \
        _box_item, _box_back, _box_bottom
    while True:
        os.system("clear")
        print()
        _box_top("⏰  RKN-GUARD  •  РАСПИСАНИЕ АВТООБНОВЛЕНИЯ СПИСКОВ")
        _box_row(f"  Сейчас: {CYAN}{_rg_schedule_show()}{NC}")
        r = _run(["systemctl", "list-timers", RG_TIMER, "--no-pager", "--no-legend"],
                 capture=True, timeout=15)
        for l in (r.stdout or "").splitlines():
            if RG_TIMER in l:
                _box_row(f"  {DIM}{l.strip()[:70]}{NC}")
        _box_sep()
        _box_row(f"  {DIM}Таймер запускает main.py --rkn-update: обновление{NC}")
        _box_row(f"  {DIM}--managed-lists + слияние /etc/ipset.conf (защита{NC}")
        _box_row(f"  {DIM}химерных секций от затирания).{NC}")
        _box_sep()
        _box_item("1", "Обновить сейчас")
        _box_item("2", "Каждые N часов (1–168)")
        _box_item("3", "В заданные времена (МСК, список)")
        _box_item("4", "Ежедневно в 06:00 (МСК)")
        _box_item("5", "Ежедневно в 06:00 (локальное время сервера)")
        _box_item("6", "Отключить автообновление")
        _box_back()
        _box_bottom()
        ch = _input(f"{CYAN}Выбор: {NC}").lower()
        if ch in ("q", ""):
            return
        if ch == "1":
            _rg_update_now()
            time.sleep(1)
        elif ch == "2":
            v = _input("Интервал в часах (1–168): ")
            _rg_schedule_set("interval", v)
            time.sleep(1)
        elif ch == "3":
            v = _input("Времена МСК через запятую (6,12,18 или 06:00,18:30): ")
            _rg_schedule_set("hours", v)
            time.sleep(1)
        elif ch == "4":
            _rg_schedule_set("msk", "06:00")
            time.sleep(1)
        elif ch == "5":
            _rg_schedule_set("local", "06:00")
            time.sleep(1)
        elif ch == "6":
            _rg_schedule_set("off", "")
            time.sleep(1)


# ═════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ [RG]
# ═════════════════════════════════════════════════════════════════════════════
def do_manage_rkn_guard() -> None:
    """TUI меню — точка входа из _core.py «Безопасность и автоматизация» [RG].

    Все опции rkn-guard интерактивны: установка, списки (базовые/доп.),
    обновление (сейчас/расписание), ручные баны, исключения, статистика/
    журналы, логирование, firewall-бэкенд, панель, обновление бинарника
    (релизы/исходники), переустановка, удаление.
    """
    from chimera.modules.box_renderer import (
        _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
    )
    while True:
        os.system("clear")
        st = _rg_state_load()
        installed = _rg_installed()
        active = installed and _rg_rules_active()
        ver, branch = _rg_version() if installed else ("", "")

        # ── статус-панель ──
        if active:
            backend = _rg_backend()
            label = _FIREWALL_LABELS.get(backend, backend)
            if backend == "iptables" and shutil.which("ufw"):
                r = _run(["ufw", "status"], capture=True, timeout=15)
                if "Status: active" in (r.stdout or ""):
                    label = "UFW (iptables + ipset)"
            status_str = f"{GREEN}● активен{NC}  {DIM}· {label}{NC}"
        elif installed:
            status_str = f"{YELLOW}⚠ установлен, правил нет{NC}"
        else:
            status_str = f"{DIM}○ не установлен{NC}"

        total, upd = _rg_subnets_total() if installed else (0, "")
        pkts4, pkts6 = _rg_drop_counters() if active else (0, 0)
        log_on, rsys = _rg_logging_active() if installed else (False, False)
        logging_str = (f"{GREEN}вкл{NC} {DIM}(rsyslog+logrotate+aggregate)"
                       if log_on else f"{DIM}выкл{NC}") if installed else f"{DIM}—{NC}"
        if log_on and not rsys:
            logging_str += f" {YELLOW}rsyslog не активен!{NC}"
        sched_str = _rg_schedule_show() if installed else "—"
        manual_n = _rg_manual_count()
        exc_n = _rg_exceptions_count() if installed else 0
        panel_str = (f"{GREEN}привязана{NC}" if _rg_panel_bound()
                     else f"{DIM}нет{NC}") if installed else "—"

        print()
        _box_top("🛡️  RKN-GUARD  •  ПОДСЕТИ РКН/ТСПУ/СКИПА/СКАНЕРОВ — DROP НА ВХОДЕ")
        _box_row(f"  {DIM}Порт Flecksis/rkn-guard в Chimera: сканеры РКН не "
                 f"докажутся до{NC}")
        _box_row(f"  {DIM}xray/mita — SYN дропается на входе, «хост не "
                 f"отвечает».{NC}")
        _box_sep()
        _box_row(f"  Статус:          {status_str}")
        if installed:
            _box_row(f"  Версия:          {CYAN}{ver}{NC} {DIM}· ветка {branch}{NC}")
            _box_row(f"  Подсетей:        {CYAN}{total}{NC} "
                     f"{DIM}(обновлены {upd} МСК){NC}")
            _box_row(f"  Дропов:          {CYAN}{pkts4}{NC} IPv4 · "
                     f"{CYAN}{pkts6}{NC} IPv6 {DIM}(счётчики правил){NC}")
            _box_row(f"  Логирование:     {logging_str}")
            _box_row(f"  Автообновление:  {sched_str}")
            _box_row(f"  Ручных банов:    {manual_n}   "
                     f"{DIM}исключений: {exc_n}{NC}")
            _box_row(f"  Панель (Win):    {panel_str}")
            _box_row(f"  {DIM}Установлен: {st.get('installed_at', '')}{NC}")
        _box_sep()
        if not installed:
            _box_item("I", "⚡ Установить rkn-guard (бинарник + списки + правила)")
            _box_sep()
            _box_row(f"  {DIM}Установка: ~4.4k CIDR из 5 базовых списков; "
                     f"дефолт —{NC}")
            _box_row(f"  {DIM}iptables+ipset (единый стек Химеры, UFW-"
                     f"интеграция через{NC}")
            _box_row(f"  {DIM}before.rules, восстановление ipset при ребуте).{NC}")
            _box_sep()
        else:
            _box_item("1", "📊 Статистика и журналы  (дропы, топ атакующих)")
            _box_item("2", "📋 Списки подсетей  (базовые 5 + доп. источники)")
            _box_item("3", "🔄 Обновить списки сейчас  (без сброса счётчиков)")
            _box_item("4", "⏰ Расписание автообновления  (часы/МСК-времена/выкл)")
            _box_item("5", "🚫 Ручные баны IP  (manual-ips)")
            _box_item("6", "✅ Исключения  (IP/протокол/порт — проход мимо блоков)")
            _box_item("7", f"📝 Логирование дропов: "
                           f"{'выключить' if log_on else 'включить'}")
            _box_item("8", "🔥 Firewall-бэкенд  (iptables/nftables/firewalld/auto)")
            _box_item("9", "🖥️  Панель rkn-guard-panel (привязка / отзыв)")
            _box_item("U", "⬆️  Обновить с апстрима  (бинарник: релизы/исходники)")
            _box_item("R", "🔁 Переустановить  (сохраняя списки/баны/исключения)")
            _box_item("X", "🗑️  Удалить rkn-guard")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if ch in ("q", "", "0"):
            break

        if ch == "i" and not installed:
            _rg_install_interactive()
            input(f"{BLUE}Нажмите Enter…{NC}")
        elif installed:
            if ch == "1":
                _rg_menu_stats()
            elif ch == "2":
                _rg_menu_lists()
            elif ch == "3":
                _rg_update_now()
                input(f"{BLUE}Нажмите Enter…{NC}")
            elif ch == "4":
                _rg_menu_schedule()
            elif ch == "5":
                _rg_menu_manual()
            elif ch == "6":
                _rg_menu_exceptions()
            elif ch == "7":
                _rg_toggle_logging(st)
                input(f"{BLUE}Нажмите Enter…{NC}")
            elif ch == "8":
                _rg_menu_firewall()
            elif ch == "9":
                _rg_menu_panel()
            elif ch == "u":
                _rg_menu_update_binary()
            elif ch == "r":
                if _confirm("Переустановить rkn-guard (правила пересоздаются, "
                            "списки/баны/исключения сохраняются)?", False):
                    _rg_uninstall_flow(remove_logs=False, interactive=False)
                    _rg_install_flow(st, interactive=False)
                    input(f"{BLUE}Нажмите Enter…{NC}")
            elif ch == "x":
                rm_logs = _confirm("Удалить также журналы и накопленную "
                                  "статистику дропов?", False)
                _rg_uninstall_flow(remove_logs=rm_logs, interactive=True)
                input(f"{BLUE}Нажмите Enter…{NC}")


def _rg_install_interactive() -> None:
    """Интерактивная установка: выбор бэкенда/списков/логирования/расписания."""
    st = _rg_state_load()
    print()
    _info("Базовые списки (5, ~4.4k CIDR): гос-сети РКН, ручные сканеры, "
          "СКИПА-пойнты, AS-сети ТСПУ (C24Be), CyberOK — потребительские AS "
          "не затронуты")
    print()
    print(f"  Firewall-бэкенд:")
    print(f"   {CYAN}1{NC}. iptables + ipset  {DIM}(дефолт Химеры: единый стек "
          f"с ingress_geoip/ipban/port_knocking, UFW-интеграция){NC}")
    print(f"   {CYAN}2{NC}. nftables          {DIM}(отдельная таблица inet "
          f"rkn_guard){NC}")
    print(f"   {CYAN}3{NC}. firewalld          {DIM}(бэкенд nftables){NC}")
    print(f"   {CYAN}4{NC}. auto               {DIM}(текущий инструмент; чистый "
          f"сервер → nftables){NC}")
    fw = _input(f"{BOLD}Выбор [1]:{NC} ", "1")
    backend = {"1": "iptables", "2": "nftables", "3": "firewalld",
               "4": "auto", "iptables": "iptables", "nftables": "nftables",
               "firewalld": "firewalld", "auto": "auto"}.get(fw, "iptables")
    if backend == "auto":
        r = _rg_run(["firewall-select", "auto"], timeout=60)
        backend = (r.stdout or "").strip().splitlines()[0] if r.returncode == 0 \
            else "iptables"
        _info(f"Автоопределение: {backend}" + 
              ("" if backend == "iptables" else
               f" {YELLOW}(на Химере рекомендован iptables+ipset){NC}"))
    st["firewall"] = backend

    log = _confirm("Логировать дропы (rsyslog → журналы, статистика атакующих)?",
                   default_yes=True)
    st["logging"] = log

    sched = _confirm("Включить автообновление списков ежедневно в 06:00 МСК?",
                     default_yes=True)
    if sched:
        st["schedule_mode"] = "msk"
        st["schedule_value"] = "06:00"

    if not _rg_install_flow(st, interactive=True):
        return

    if not sched:
        print()
        _info("Расписание можно включить в меню [4] (каждые N часов / список "
              "времён МСК / локальное)")


def _rg_toggle_logging(st: dict) -> None:
    """Вкл/выкл логирования дропов: re-run full с/без --enable-logging.

    full идемпотентен: сеты заменяются swap'ом, цепочка/managed-блок в
    before.rules перегенерируются (без LOG-правила при выключении),
    счётчики дропов правила DROP остаются (правило не пересоздаётся при
    наличии). ipset.conf — под merge-компенсацией.
    """
    on, _ = _rg_logging_active()
    target = not on
    print()
    _info(f"{'Включаю' if target else 'Выключаю'} логирование дропов "
          f"(перегенерация правил)…")
    st["logging"] = target
    st["firewall"] = _rg_backend()
    ok = _rg_install_flow(st, interactive=False)
    if ok:
        _success(f"Логирование: {'вкл (rsyslog + aggregate CSV 30с)' if target else 'выкл'}")
    else:
        _warn("Не удалось переключить — статус не изменился")
