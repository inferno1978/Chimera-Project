"""
chimera/modules/mieru_cascade.py
───────────────────────────────────────────────────────────────────────────────
Mieru Cascade — серверный каскад Entry→Exit для standalone-Mieru (не аддон).

Реализует схему, заложенную в докстринге modules/mieru.py (задел был только
на бумаге, кода не существало — см. MIERU-1 в worklog проекта):

  Клиент ──mTLS──► mita Entry (RU, standalone-Mieru)
                     │  после расшифровки mita набирает цель
                     │  iptables: cgroup/owner-match по процессу mita
                     │  → REDIRECT → redsocks (127.0.0.1)
                     ▼
                   redsocks ──SOCKS5──► mieru-hop (клиент, 127.0.0.1)
                     │  mTLS + padding
                     ▼
                   mita Exit (EU, standalone-Mieru, hop-пользователь)
                     │
                     ▼
                   Интернет (exit-IP = EU-нода)

ПРАВИЛА БЕЗОПАСНОСТИ (петли и чужой трафик):
  • Редирект матчит ТОЛЬКО процесс mita (cgroup system.slice/mita.service;
    fallback — owner uid 'mita' через drop-in User=mita). redsocks и
    mieru-hop работают от root → в петлю не попадают.
  • 127.0.0.0/8 исключён guard-правилом (DNS mita на loopback и т.п.).
  • Правила добавляются В КОНЕЦ nat OUTPUT — ПОСЛЕ существующих правил
    Chimera (dnscrypt-RETURN, TG-REDIRECT в xray-каскад) → вся существующая
    маршрутизация сохраняет приоритет; каскад ловит только остаток.
  • TCP-нога — через Exit. UDP-нагрузка mita идёт напрямую с Entry
    (redsocks не умеет UDP) — опция strict_udp_block позволяет её
    блокировать, чтобы не светить RU-IP случайно (по умолчанию выкл).

MULTI-EXIT:
  • Несколько Exit-нод: по паре (redsocks + mieru-hop) на каждую.
  • Балансировка — iptables statistic (round-robin по соединениям),
    стратегия 'prio' — active-backup (только первый живой Exit).
  • СОСТАВ БАЛАНСИРОВКИ (lb_exits, порт awg_cascade_lb 06.10):
    балансировать между ВЫБРАННЫМИ Exit-ами (пара/тройка/подмно-
    жество — из всего списка); st['lb_exits'] = [ids], пусто = все;
    <2 валидных → фолбэк на все. Меню [E] / set_lb_exits(ids|метки).
    Пиннинг ортогонален: закреплённый вне состава — работает.
  • Health-timer (*/1 мин): TCP-проба + E2E `mieru test` на каждый Exit;
    падение (2 подряд) исключает Exit из правил, восстановление возвращает.
  • Сериализация применений: flock (TUI-хендлеры ↔ health-тик) — гонка
    01.10 оставляла state и ядро с РАЗНЫМИ пинами. Каждый тик сверяет
    живые правила с applied_rules (iptables -S) и самозалечивает
    рассинхрон (сбой apply, ручные правки, частичный flush).

PORT_REGISTRY (требование владельца):
  • Активация/apply: port_register() на каждый loopback-порт
    (socks/redsocks/rpc/http) — проверка занятости БЕЗ force.
  • Деактивация/удаление: ufw_close_port() + port_unregister().

DOWNLOAD MANAGER (требование владельца):
  • redsocks — .deb из пула дистрибутива через PackageSpec
    (mieru_cascade_packages.py; fallback — apt-get с честным warn).
  • mieru-клиент (нужен на Entry) — через зеркала mieru_mirrors.

ПРОВИДЕНИНГ (паттерн awg_cascade, без SSH-автоматизации):
  • Exit-нода: меню [2] — standalone-Mieru + hop-пользователь; данные
    выводятся рамкой для переноса на Entry вручную.
  • Entry-нода: меню [1] → [3] добавить Exit-ы → [4] применить.

ОБФУСКАЦИЯ (паритет с mieru addon / hybrid_addon):
  • Exit: выбор пресета mita при настройке роли (disabled/basic/medium/
    aggressive/custom JSON) — тот же набор, что «Пресеты обфускации»
    standalone-Mieru; итог виден в рамке EXIT НАСТРОЕН.
  • Entry: пресет хопа ПЕР-EXIT (добавление/смена в [3]); рекомендуется
    равный пресету mita на Exit (живой тест: mieru толерантен к
    рассинхрону, но совпадение = предсказуемая симметрия ног).
  • Legacy-фолбэк: Exit без hop_preset → пресет standalone-установки
    Entry (данные, сохранённые до per-Exit пресетов).

КЛИЕНТСКАЯ ВЫДАЧА (порт hybrid_addon._show_mieru_client_links):
  • После успешного [4] Применить (Entry) и [2] Exit-настройки:
    Karing mierus:// (+ traffic-pattern blob из `mita export
    traffic-pattern`), Nekobox/Nyamebox mierus://, sing-box JSON для
    Karing (запасной, dns-секция из standalone-state, BOTH → selector),
    QR. UDP для Karing — с IP (баг ядра Karing). Повторно — меню [L]
    с выбором пользователя; hop-юзер в прямую выдачу не попадает.

Точка входа: из mieru.py (меню standalone-Mieru, пункт [C]) —
    from chimera.modules.mieru_cascade import do_mieru_cascade_menu
    do_mieru_cascade_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import fcntl
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

from chimera.modules.proto_common import (
    ProtoCancelled,
    proto_load_state, proto_save_state,
    proto_ask, proto_gen_password, proto_ipt_persist,
    proto_ipt_rule_exists, proto_get_latest_version,
)
from chimera.modules.port_registry import (
    port_register, port_unregister, port_list_for_service,
    ufw_close_port, SERVICE_MIERU_CASCADE,
)

# ══════════════════════════════════════════════════════════════════════════════
#  ЛЕНИВЫЕ ДОСТУПЫ (как в mieru_dpi: mieru.py грузится первым из _core.py,
#  прямой импорт здесь создал бы цикл)
# ══════════════════════════════════════════════════════════════════════════════

def _mieru():
    """mieru — константы, боксы, цвета, пресеты, standalone-функции."""
    from chimera.modules import mieru
    return mieru


# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════

_MODULE_STATE = Path("/var/lib/xray-installer/mieru_cascade.json")

_REDSOCKS_CONF  = Path("/etc/redsocks.conf")   # системный конфиг пакета redsocks

_ETC_DIR        = Path("/etc/mieru-cascade")
_ROUTING_SH     = _ETC_DIR / "routing.sh"
_HEALTH_WRAPPER = Path("/usr/local/bin/mieru-cascade-health.sh")
_INST_DIR       = Path("/var/lib/mieru-cascade")     # HOME инстансов mieru-hop

_UNIT_HOP       = Path("/etc/systemd/system/mieru-hop@.service")
_UNIT_REDSOCKS  = Path("/etc/systemd/system/mieru-cascade-redsocks@.service")
_UNIT_ROUTING   = Path("/etc/systemd/system/mieru-cascade-routing.service")
_UNIT_HEALTH    = Path("/etc/systemd/system/mieru-cascade-health.service")
_UNIT_HEALTH_T  = Path("/etc/systemd/system/mieru-cascade-health.timer")

_MITA_DROPOIN_DIR = Path("/etc/systemd/system/mita.service.d")
_MITA_DROPOIN     = _MITA_DROPOIN_DIR / "60-mieru-cascade-user.conf"

_MITA_CGROUP = "system.slice/mita.service"

# B4-EXEMPT: освобождение блок-листа mieru_dpi из каскада (двухплечевой
# сплит, паритет с VLESS+B4 — живой кейс 01.10.2026). Домены включённых
# сетов b4 (state mieru_dpi.route_domains — тот же список, что в
# клиентских конфигах [6]) резолвятся в ipset; TCP mita в эти IP идёт
# НАПРЯМУЮ с Entry (b4 дурит ТСПУ на плече нода→цель, цель видит RU-IP),
# остальное — как раньше, в Exit-ы через redsocks.
_B4_IPSET     = "mieru_b4_direct"
_B4_IPSET_TMP = _B4_IPSET + "_new"
_B4_RESOLVE_MAX_WORKERS = 16
_B4_RESOLVE_OVERALL_S   = 25      # потолок фазы резолва (все виды, сек)
_B4_CURL_TIMEOUT_S      = 4       # один DoH-запрос через hop-socks
# querylog-harvest (клиентский вид, живой кейс 02.10.2026): AGH
# ставится chimera-ой в /opt/AdGuardHome (aghome_setup.AGH_WORK_DIR);
# /var/lib — фолбэк для ручных установок. Читаем ХВОСТ файла (90-дневный
# retention может отращивать сотни МБ) и берём записи свежее окна.
_B4_QLOG_PATHS    = (Path("/opt/AdGuardHome/data/querylog.json"),
                     Path("/var/lib/AdGuardHome/data/querylog.json"))
_B4_QLOG_TAIL_B   = 4 * 1024 * 1024   # хвост querylog.json за один тик
_B4_QLOG_WINDOW_S = 24 * 3600         # окно свежести записей (сек)

# Loopback-окна (запас 50 на тип; rpc/http — плейсхолдеры конфига,
# слушаются только если mieru proxy поднимает их — проверяется на деплое)
_SOCKS_BASE,     _SOCKS_MAX     = 24081, 24130
_REDSOCKS_BASE,  _REDSOCKS_MAX  = 23081, 23130
_RPC_BASE,       _RPC_MAX       = 25081, 25130
_HTTP_BASE,      _HTTP_MAX      = 25181, 25230

_E2E_URL = "https://www.youtube.com"
_PROBE_TIMEOUT = 40        # сек, как в mieru_dpi._e2e_probe
_TCP_PROBE_TIMEOUT = 3.0

_RE_LABEL = re.compile(r"^[A-Za-z0-9_-]{1,24}$")
_RE_HOST = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$"
)

DEFAULT_HOP_USERNAME = "cascade_hop"

# ══════════════════════════════════════════════════════════════════════════════
#  БАЛАНСИРОВКА EXIT-ОВ: стратегии (порт из smart_balancer VLESS, 01.10)
#
#  Ядерные (распределяет iptables, пересчёт не нужен):
#    rr        — statistic nth, по очереди на соединение
#    random    — statistic random, равномерно случайно на соединение
#    prio      — active-backup, только первый живой Exit
#  Весовые (доли ∝ 1/метрика, weighted random, пересчёт в health
#  tick каждую минуту; все живые Exit-ы остаются в ротации —
#  агрегация каналов сохраняется, в отличие от VLESS-балансировщика,
#  где xray держит один активный outbound):
#    leastping — доли ∝ 1/latency_ms (health-пробы)
#    leastload — доли ∝ 1/(1+established на хопе)
#    smart     — доли ∝ 1/score (пинг+TTFB+нагрузка) ★ как VLESS
#  Веса score и нормализация зеркальны smart_balancer.py (VLESS).
#
#  ПИННИНГ (порт CHAIN_PINNED_NODE_INDEX из dpi_detector/chain_nodes
#  VLESS, 01.10): st['pinned_exit'] = id Exit-а — весь трафик каскада
#  идёт ТОЛЬКО через него, стратегии игнорируются (как «pinned-режим»
#  VLESS: «весь трафик → нода, балансировщик выключен»). При падении
#  закреплённого Exit — fallback на первого живого (фаза B), при
#  восстановлении — автоматический возврат (фаза A). Ссылки клиентов
#  НЕ меняются — пиннинг меняет только egress-маршрутизацию на Entry.
# ══════════════════════════════════════════════════════════════════════════════
BALANCE_STRATEGIES = ("rr", "random", "prio", "leastping", "leastload", "smart")
METRIC_STRATEGIES = ("leastping", "leastload", "smart")

# Веса составной оценки — зеркально smart_balancer (VLESS)
_B_W_LATENCY = 0.50
_B_W_BANDWIDTH = 0.30
_B_W_LOAD = 0.20
_B_NORM_LAT_MS = 2000      # «худший» пинг, мс
_B_NORM_TTFB_MS = 5000     # «худший» TTFB через хоп, мс
_B_NORM_LOAD = 200         # «худшая» нагрузка, established
_B_SHARE_FLOOR = 0.005     # квант доли: ниже 0.5% — Exit вне ротации
_B_SCORE_FLOOR = 0.002     # флор score: кап соотношения весов 500:1
                           # (анти-доминирование одного Exit; 0.02 сглаживал
                           #  хорошие Exit-ы в равные доли — баг 01.10)
_TTFB_URLS = (
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
    "http://detectportal.firefox.com/success.txt",
)


def _prob_str(p: float) -> str:
    """Единый формат вероятности iptables statistic --probability.
    Один helper для создания, хранения (applied_rules) и зачистки —
    строки идентичны, -D совпадает байт-в-байт."""
    p = max(min(p, 1.0), 0.0001)
    return f"{p:.4f}"


# ══════════════════════════════════════════════════════════════════════════════
#  RUN + STATE
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: list, capture: bool = False, check: bool = False,
         timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if timeout:
        kw["timeout"] = timeout
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


def state_load() -> dict:
    return proto_load_state(_MODULE_STATE, defaults={
        "role": "",                # "" | entry | exit
        "matcher": None,           # None | "cgroup" | "owner"  (entry)
        "strategy": "rr",          # rr | random | prio | leastping | leastload | smart   (entry)
        "strict_udp_block": False, # (entry)
        "exits": [],               # (entry)
        "exit": {},                # (exit-нода)
        "lb_exits": [],            # ids Exit-ов для балансировки; [] = все (entry)
    })


def state_save(st: dict) -> None:
    proto_save_state(_MODULE_STATE, st)


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ══════════════════════════════════════════════════════════════════════════════
#  MATCHER: cgroup (первичный) / owner (fallback)
# ══════════════════════════════════════════════════════════════════════════════

def _probe_cgroup() -> bool:
    """Живая проба: -m cgroup --path поддерживается ядром/iptables?

    Проверено на прод-серверах проекта (Ubuntu 24.04, iptables 1.8.10
    nf_tables): rc=0 на A/B/DE. Проба безвредна: правило добавляется и
    тут же удаляется.
    """
    spec = ["-m", "cgroup", "--path", _MITA_CGROUP, "-j", "RETURN"]
    r = _run(["iptables", "-t", "nat", "-A", "OUTPUT"] + spec, capture=True)
    if r.returncode != 0:
        return False
    _run(["iptables", "-t", "nat", "-D", "OUTPUT"] + spec)
    return True


def _mita_uid() -> Optional[int]:
    r = _run(["id", "-u", "mita"], capture=True)
    if r.returncode == 0:
        try:
            return int((r.stdout or "").strip())
        except ValueError:
            return None
    return None


def _apply_owner_dropin() -> bool:
    """Fallback-режим: mita работает от юзера mita (owner-match).

    Требуется только если -m cgroup не поддерживается. Меняет юзера
    сервиса через drop-in (не трогая юнит standalone-модуля) + chown
    /etc/mita (конфиг должен читаться процессом) + рестарт mita.
    """
    m = _mieru()
    m._ensure_mita_user()
    _MITA_DROPOIN_DIR.mkdir(parents=True, exist_ok=True)
    _MITA_DROPOIN.write_text(
        "# mieru_cascade: owner-match fallback (cgroup не поддерживается)\n"
        "# Юнит standalone-Mieru не тронут — drop-in переопределяет юзера.\n"
        "[Service]\n"
        "User=mita\n"
        "Group=mita\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
    )
    # конфиг mita должен читаться новым юзером
    _run(["chown", "-R", "mita:mita", str(m._CFG_DIR)])
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "restart", m._SERVICE_NAME])
    time.sleep(1)
    r = _run(["systemctl", "is-active", m._SERVICE_NAME], capture=True)
    return (r.stdout or "").strip() == "active"


def _remove_owner_dropin() -> None:
    """Откат fallback-режима (uninstall)."""
    m = _mieru()
    _MITA_DROPOIN.unlink(missing_ok=True)
    if not any(_MITA_DROPOIN_DIR.iterdir()):
        _MITA_DROPOIN_DIR.rmdir()
    _run(["chown", "-R", "root:root", str(m._CFG_DIR)])
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "restart", m._SERVICE_NAME])


def _matcher_args(st: dict) -> Optional[list]:
    """argv-фрагмент матчинга процесса mita для iptables-правил."""
    mode = st.get("matcher")
    if mode == "cgroup":
        return ["-m", "cgroup", "--path", _MITA_CGROUP]
    if mode == "owner":
        uid = _mita_uid()
        if uid is None:
            return None
        return ["-m", "owner", "--uid-owner", str(uid)]
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГИ: redsocks + mieru-hop (схема как в mieru_dpi._e2e_probe)
# ══════════════════════════════════════════════════════════════════════════════

def _redsocks_conf(exit_node: dict) -> str:
    """redsocks.conf для одного Exit (один блок redsocks — один инстанс
    демона на Exit; daemon=off для systemd Type=simple).

    БЕЗ комментариев: парсер redsocks не понимает '#' — «file parsing
    error at line 1: unexpected char» (баг деплоя 01.10, live B).
    Скобки redsocks-синтаксиса конфликтуют с f-string — конкатенация.
    """
    up_login = exit_node.get("socks_login", "") or ""
    up_pass = exit_node.get("socks_password", "") or ""
    return (
        "base {\n"
        "    log_debug = off;\n"
        "    log_info = on;\n"
        "    log = \"syslog:daemon\";\n"
        "    daemon = off;\n"
        "    redirector = iptables;\n"
        "}\n"
        "redsocks {\n"
        "    local_ip = 127.0.0.1;\n"
        "    local_port = " + str(exit_node.get("redsocks_port", 0)) + ";\n"
        "    ip = 127.0.0.1;\n"
        "    port = " + str(exit_node.get("socks_port", 0)) + ";\n"
        "    type = socks5;\n"
        "    login = \"" + up_login + "\";\n"
        "    password = \"" + up_pass + "\";\n"
        "}\n"
    )


def _hop_client_config(exit_node: dict, pattern_cfg: Optional[dict]) -> dict:
    """Конфиг mieru-клиента ( hop-инстанс на Entry → Exit-нода).

    Схема валидирована реальным клиентом в mieru_dpi._e2e_probe
    (apply config + env HOME/XDG_CONFIG_HOME-изоляция).
    """
    profile = {
        "profileName": "hop-" + exit_node.get("id", "x"),
        "user": {
            "name": exit_node.get("username", ""),
            "password": exit_node.get("password", ""),
        },
        "servers": [{
            "ipAddress": exit_node.get("host", ""),
            "portBindings": [{
                "port": int(exit_node.get("port", 2012)),
                "protocol": (exit_node.get("protocol") or "TCP").upper(),
            }],
        }],
        "mtu": 1400,
        "multiplexing": {"level": "MULTIPLEXING_HIGH"},
    }
    if pattern_cfg:
        profile["trafficPattern"] = pattern_cfg
    return {
        "profiles": [profile],
        "activeProfile": profile["profileName"],
        "rpcPort": int(exit_node.get("rpc_port", 0)) or 25081,
        "socks5Port": int(exit_node.get("socks_port", 0)) or 24081,
        "httpProxyPort": int(exit_node.get("http_port", 0)) or 25181,
        "loggingLevel": "INFO",
    }


def _instance_dir(exit_node: dict) -> Path:
    return _INST_DIR / exit_node["id"]


def _seed_hop_instance(exit_node: dict, pattern_cfg: Optional[dict]) -> bool:
    """Создаёт/обновляет изолированный HOME инстанса и применяет конфиг
    через `mieru apply config` (заодно валидация со стороны клиента)."""
    m = _mieru()
    d = _instance_dir(exit_node)
    (d / ".config").mkdir(parents=True, exist_ok=True)
    cfg = _hop_client_config(exit_node, pattern_cfg)
    with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False) as tmp:
        tmp.write(json.dumps(cfg, indent=2))
        tmp_path = Path(tmp.name)
    try:
        env = dict(os.environ)
        env["HOME"] = str(d)
        env["XDG_CONFIG_HOME"] = str(d / ".config")
        r = subprocess.run(
            [str(m._MIERU_BIN), "apply", "config", str(tmp_path)],
            capture_output=True, text=True, check=False, timeout=30, env=env)
        if r.returncode != 0:
            detail = ((r.stderr or r.stdout or "").strip())[:300]
            print(f"  [!] mieru apply config ({exit_node['label']}): {detail}")
            return False
        return True
    finally:
        tmp_path.unlink(missing_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
#  B4-EXEMPT: блок-лист mieru_dpi мимо каскада (паритет с VLESS+B4)
#
#  Задача (живой кейс 01.10.2026): сплит-конфиг клиента шлёт блок-лист
#  на RU-ноду, чтобы его ловил b4 (ломает логику ТСПУ на плече
#  нода→цель, цель видит RU-IP — у юзера вместо этого весь mita-TCP
#  уезжал в Exit-ы). Каскад матчит ВЕСЬ TCP mita по cgroup — без
#  освобождения блок-лист тоже каскадится. Механизм: домены
#  route_domains (mieru_dpi) резолвятся в ipset _B4_IPSET; nat OUTPUT:
#  dst ∈ ipset → RETURN (direct с Entry; b4 процессо-агностичен —
#  Xray, curl или mita без разницы), остальное → REDIRECT Exit-ов.
#
#  ВИДЫ РЕЗОЛВА (критично для CDN-геостеринга): клиент NyameBox/Iblis
#  резолвит домены САМ (remote_dns tls://8.8.8.8 ЧЕРЕЗ туннель → Exit →
#  вид 8.8.8.8 с гео Exit-а; sniff в приложении НЕ подменяет назначение
#  для прокси — ConfigBuilder.cpp:1482-1485 без override). Поэтому ipset
#  наполняется ОБЪЕДИНЕНИЕМ видов:
#    • RU-вид: системный резолвер ноды (AGH) — так резолвит сам mita
#      для доменных назначений (socks5h/Karing с DoH
#      cdn2.example:30443 = тот же AGH);
#    • Exit-вид на каждый Exit: DoH-JSON 8.8.8.8 ЧЕРЕЗ hop-socks этого
#      Exit — ровно то, что получит реальный клиент каскада;
#    • Клиентский вид (querylog-harvest, живой кейс 02.10.2026):
#      пер-видео имена rr*.googlevideo.com в route_domains НЕТ — их
#      GGC-кэши (IP вне AS15169, у провайдера клиента) базовый
#      резолв не видит, ~100% промах ipset → весь видеотрафик
#      каскадился через Exit обратно к RU GGC → спиннеры. DoH
#      клиента приходит на AGH самой Entry-ноды → хвост querylog.json
#      суффикс-матчится по route_domains, A-записи ответов добираются
#      в набор (окно 24ч, чтение локального файла, без DNS-трафика).
#  Промах по всем видам = каскад (мягкая деградация, не поломка).
#  Own-IP guard: сервисы самой ноды (DoH :30443, AGH :53) не должны
#  ездить хэмпином Exit→Entry.
# ══════════════════════════════════════════════════════════════════════════════

def _b4_exempt_domains() -> list:
    """Домены блок-листа из mieru_dpi (route_domains при enabled)."""
    try:
        from chimera.modules import mieru_dpi
        dst = mieru_dpi._load_state()
        if not dst.get("enabled"):
            return []
        return [d for d in (dst.get("route_domains") or []) if d]
    except Exception:
        return []


def _b4_exempt_active(st: dict) -> bool:
    """Освобождение включено? st['b4_exempt']: None/True — авто
    (есть домены + бинарник ipset), False — выключен принудительно."""
    if st.get("b4_exempt") is False:
        return False
    if not shutil.which("ipset"):
        return False
    return bool(_b4_exempt_domains())


def _b4_own_ip() -> Optional[str]:
    """Публичный IPv4 ноды (guard от хэмпина сервисов самой ноды)."""
    try:
        ip = (_mieru()._get_server_ip() or "").strip()
    except Exception:
        return None
    return ip if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) else None


def _b4_ip_ok(ip: str) -> bool:
    """IPv4, не приватный/loopback (0.0.0.0 из «заблокированных"
    ответов AGH в ipset не кладём — матчит лишнее)."""
    try:
        p = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return (p.version == 4 and not p.is_private and not p.is_loopback
            and not p.is_unspecified and not p.is_reserved)


def _b4_resolve_ru(domain: str) -> set:
    """RU-вид: системный резолвер ноды (так же резолвит сам mita)."""
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return {ip for ip in ips if _b4_ip_ok(ip)}
    except Exception:
        return set()


def _b4_resolve_via_socks(domain: str, socks_port: int) -> set:
    """Exit-вид: DoH-JSON 8.8.8.8 ЧЕРЕЗ hop-socks Exit-а — тот же
    geosteering, что видит реальный клиент каскада (его remote_dns
    tls://8.8.8.8 ходит через туннель → Exit)."""
    url = ("https://8.8.8.8/resolve?name="
           + urllib.parse.quote(domain) + "&type=A")
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", str(_B4_CURL_TIMEOUT_S),
             "--socks5-hostname", f"127.0.0.1:{socks_port}", url],
            capture_output=True, text=True, check=False,
            timeout=_B4_CURL_TIMEOUT_S + 2)
    except Exception:
        return set()
    if r.returncode != 0 or not r.stdout:
        return set()
    try:
        data = json.loads(r.stdout)
        if data.get("Status") != 0:
            return set()
        return {a["data"] for a in data.get("Answer") or []
                if a.get("type") == 1 and _b4_ip_ok(a.get("data", ""))}
    except Exception:
        return set()


def _b4_querylog_path() -> Optional[Path]:
    """Первый существующий querylog.json AGH (нет AGH → None)."""
    for p in _B4_QLOG_PATHS:
        try:
            if p.is_file():
                return p
        except Exception:
            continue
    return None


def _b4_qlog_epoch(t: str) -> Optional[float]:
    """RFC3339 AGH (наносекунды, Z/смещение) → epoch; мусор → None."""
    if not t:
        return None
    try:
        return datetime.fromisoformat(t).timestamp()
    except ValueError:
        # python < 3.11 не ест наносекунды/Z — нормализуем вручную
        m = re.match(
            r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", t)
        if not m:
            return None
        base, frac, tz = m.groups()
        tz = (tz or "").replace("Z", "+00:00")
        if tz and ":" not in tz:          # +0300 → +03:00
            tz = tz[:3] + ":" + tz[3:]
        try:
            return datetime.fromisoformat(
                base + "." + ((frac or "") + "000000")[:6] + tz).timestamp()
        except ValueError:
            return None


def _b4_qh_suffix_match(qh: str, domains: list) -> bool:
    """QH — сам домен или его поддомен (строго по границе метки).

    Граница метки обязательна: evilgooglevideo.com НЕ матчит
    googlevideo.com — иначе чужие домены отклеились бы от каскада
    и уехали с RU-IP (деанон). Самодостаточна: нормализует оба
    аргумента (регистр/точки), безопасна для прямых вызовов."""
    qh = (qh or "").strip().lower().rstrip(".")
    if not qh:
        return False
    for d in domains:
        d = (d or "").strip().lower().rstrip(".")
        if d and (qh == d or qh.endswith("." + d)):
            return True
    return False


def _b4_dns_skip_name(msg: bytes, i: int) -> int:
    """Пропустить DNS-имя (метки/компрессия); выход за границы → -1."""
    while i < len(msg):
        n = msg[i]
        if n == 0:
            return i + 1
        if (n & 0xC0) == 0xC0:          # указатель компрессии
            return i + 2
        i += 1 + n
    return -1


def _b4_dns_a_records(msg: bytes) -> set:
    """Публичные IPv4 из A-записей DNS-ответа (wire); мусор → пусто.

    CNAME/AAAA и прочие типы пропускаются; приватные/loopback
    (0.0.0.0 «заблокировано» AGH, rebind-ответы) отсеивает _b4_ip_ok."""
    out: set = set()
    if len(msg) < 12:
        return out
    try:
        qd = int.from_bytes(msg[4:6], "big")
        an = int.from_bytes(msg[6:8], "big")
        i = 12
        for _ in range(qd):
            i = _b4_dns_skip_name(msg, i)
            if i < 0:
                return out
            i += 4                          # qtype + qclass
        for _ in range(an):
            i = _b4_dns_skip_name(msg, i)
            if i < 0 or i + 10 > len(msg):
                return out
            rtype = int.from_bytes(msg[i:i + 2], "big")
            rdl = int.from_bytes(msg[i + 8:i + 10], "big")
            i += 10
            if i + rdl > len(msg):
                return out
            if rtype == 1 and rdl == 4:
                ip = ".".join(str(b) for b in msg[i:i + 4])
                if _b4_ip_ok(ip):
                    out.add(ip)
            i += rdl
    except Exception:
        return out
    return out


def _b4_harvest_querylog(domains: list) -> tuple:
    """Клиентский вид резолва: IP из querylog AGH (живой кейс 02.10).

    Возвращает (set(ipv4), stats). Читает хвост querylog.json,
    отбирает записи, чей QH суффикс-матчит domains (route_domains),
    и добирает A-записи из Answer (base64 DNS-wire) — ровно те IP,
    что AGH выдал клиентам. Критично для rr*.googlevideo.com:
    пер-видео имена, в route_domains их нет, резолвятся в GGC-кэши
    провайдера (вне AS15169) — базовые виды их не видят. Мисскост:
    только чтение локального файла; любые сбои → пустой набор
    (мягкая деградация до прежнего поведения)."""
    stats = {"names": 0, "entries": 0, "ips": 0}
    ips: set = set()
    if not domains:
        return ips, stats
    path = _b4_querylog_path()
    if path is None:
        return ips, stats
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - _B4_QLOG_TAIL_B))
            data = f.read()
    except Exception:
        return ips, stats
    if not data:
        return ips, stats
    if size > _B4_QLOG_TAIL_B:          # первая строка обрезана — выброс
        nl = data.find(b"\n")
        data = data[nl + 1:] if nl >= 0 else b""
    lowered = [(d or "").strip().lower().rstrip(".") for d in domains]
    floor = time.time() - _B4_QLOG_WINDOW_S
    names: set = set()
    for line in data.decode("utf-8", "replace").splitlines():
        if '"QH"' not in line or '"Answer"' not in line:
            continue                      # быстрый префильтр
        try:
            rec = json.loads(line)
        except Exception:
            continue                      # метаданные-шапка AGH / битые
        qh = (rec.get("QH") or "").strip().lower().rstrip(".")
        if not qh or not _b4_qh_suffix_match(qh, lowered):
            continue
        ts = _b4_qlog_epoch(rec.get("T") or "")
        if ts is None or ts < floor:
            continue                      # за окном свежести
        b64 = rec.get("Answer") or ""
        if not b64:
            continue
        try:
            wire = base64.b64decode(b64 + "===")
        except Exception:
            continue
        got = _b4_dns_a_records(wire)
        if got:
            names.add(qh)
            stats["entries"] += 1
            ips |= got
    stats["names"] = len(names)
    stats["ips"] = len(ips)
    return ips, stats


def _b4set_ensure() -> bool:
    """Создать оба ipset (-exist): боевой + временный для swap."""
    if not shutil.which("ipset"):
        return False
    for name in (_B4_IPSET, _B4_IPSET_TMP):
        _run(["ipset", "create", name, "hash:ip", "maxelem", "65536",
              "-exist"], capture=True)
    return True


def _b4set_refresh(st: dict, verbose: bool = False) -> dict:
    """Пересобрать ipset блок-листа (все виды резолва, атомарный swap).

    Вызывается из [4]/apply и health-тика (каждую минуту): TTL CDN
    60-300с — свежесть достаточная; пустой результат (сеть легла)
    НЕ трогает старый набор. Под локом — до ~25с сети, TUI ждёт
    честно (wait_hint)."""
    stats = {"domains": 0, "views": 0, "ips": 0, "failed": 0}
    domains = _b4_exempt_domains()
    stats["domains"] = len(domains)
    if not domains or not _b4set_ensure():
        return stats
    ports = [int(e["socks_port"]) for e in st.get("exits", [])
             if e.get("enabled", True) and e.get("healthy") is not False
             and e.get("socks_port")]
    stats["views"] = 1 + len(ports)
    ips: set = set()
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=_B4_RESOLVE_MAX_WORKERS) as ex:
        futs = [ex.submit(_b4_resolve_ru, d) if p == 0
                else ex.submit(_b4_resolve_via_socks, d, p)
                for d in domains for p in [0] + ports]
        try:
            for f in concurrent.futures.as_completed(
                    futs, timeout=_B4_RESOLVE_OVERALL_S):
                try:
                    ips |= f.result(timeout=1)
                except Exception:
                    stats["failed"] += 1
        except concurrent.futures.TimeoutError:
            stats["failed"] += sum(1 for f in futs if not f.done())
    # Клиентский вид (querylog AGH): добираем IP, которые реальные
    # клиенты получили от AGH Entry-ноды (rr*.googlevideo.com → GGC).
    # Мерж ДО guard'а пустого набора: резолв лег, но querylog жив —
    # снапшот всё равно собирается (и наоборот); пусто ОБА — не трогаем.
    try:
        harvested, hstats = _b4_harvest_querylog(domains)
    except Exception:
        harvested, hstats = set(), {"names": 0, "entries": 0, "ips": 0}
    stats["qlog_names"] = hstats["names"]
    stats["qlog_entries"] = hstats["entries"]
    stats["qlog_ips"] = hstats["ips"]
    ips |= harvested
    if not ips:
        return stats           # полностью пустой набор — не трогаем старый
    _run(["ipset", "create", _B4_IPSET_TMP, "hash:ip", "maxelem",
          "65536", "-exist"], capture=True)
    _run(["ipset", "flush", _B4_IPSET_TMP], capture=True)
    try:
        subprocess.run(
            ["ipset", "restore", "-exist"],
            input="".join(f"add {_B4_IPSET_TMP} {ip}\n"
                          for ip in sorted(ips)),
            capture_output=True, text=True, check=False, timeout=30)
    except Exception:
        pass
    _run(["ipset", "swap", _B4_IPSET_TMP, _B4_IPSET], capture=True)
    _run(["ipset", "flush", _B4_IPSET_TMP], capture=True)
    stats["ips"] = len(ips)
    if verbose:
        print(f"  b4-exempt ipset: {len(ips)} IP из {stats['views']} "
              f"видов ({stats['domains']} доменов, промахов "
              f"{stats['failed']}) + querylog {hstats['ips']} IP "
              f"({hstats['names']} имён, {hstats['entries']} записей)")
    return stats


def _b4set_destroy() -> None:
    for name in (_B4_IPSET, _B4_IPSET_TMP):
        _run(["ipset", "destroy", name], capture=True)


# ══════════════════════════════════════════════════════════════════════════════
#  ОБФУСКАЦИЯ (traffic pattern) — паритет с mieru addon (hybrid_addon)
#  Меню пресетов + custom JSON + per-Exit паттерн хопа + серверный пресет Exit
# ══════════════════════════════════════════════════════════════════════════════

def _read_multiline_json() -> Optional[str]:
    """Многострочный ввод JSON до пустой строки (порт hybrid_addon).

    None при EOF без единой строки — вызывающий код не уйдёт в цикл."""
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            return "\n".join(lines) if lines else None
        if line.strip() == "":
            if lines:
                break
            continue          # пустые строки до начала ввода — пропускаем
        lines.append(line)
    return "\n".join(lines)


def _ask_pattern_menu(m, current: str = "basic",
                      subject: str = "хопа") -> tuple:
    """Меню обфускации (как в аддоне/hybrid_addon + пресеты mieru.py).

    Возвращает (preset_name, custom_cfg):
      preset_name — 'disabled'|'basic'|'medium'|'aggressive'|'custom'
      custom_cfg  — dict только для custom, иначе None
    Enter = текущее значение (current)."""
    presets = m._MIERU_TRAFFIC_PRESETS      # disabled/basic/medium/aggressive
    names = list(presets.keys())
    default_idx = names.index(current) if current in names else 1

    print(f"  {m.CYAN}Обфускация {subject} (traffic pattern):{m.NC}")
    for i, name in enumerate(names, 1):
        p = presets[name]
        marker = f" {m.GREEN}← текущий{m.NC}" if name == current else ""
        print(f"     {m.DIM}[{i}]{m.NC} {p['label']}{marker}")
        print(f"         {m.DIM}{p['description']}{m.NC}")
    print(f"     {m.DIM}[{len(names) + 1}]{m.NC} Custom — вставить свой JSON")
    raw = proto_ask(f"  {m.CYAN}Выбор [Enter={default_idx + 1}]: {m.NC}",
                    default=str(default_idx + 1), c=True).strip()

    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(names):
            return names[idx], None
        if idx == len(names):
            return "custom", _ask_pattern_custom(m)
    print(f"  {m.YELLOW}⚠{m.NC} неизвестный выбор — оставляю "
          f"'{current}'")
    return current, None


def _ask_pattern_custom(m) -> Optional[dict]:
    """Custom trafficPattern JSON (порт hybrid_addon._traffic_pattern_custom).
    None = ввод не удался → вызывающий код оставит дефолт."""
    while True:
        print(f"  {m.CYAN}Вставьте trafficPattern JSON "
              f"(пустая строка — завершить):{m.NC}")
        raw = _read_multiline_json()
        if raw is None:
            print(f"  {m.YELLOW}⚠{m.NC} ввод прерван — Basic")
            return None
        if not raw.strip():
            print(f"  {m.YELLOW}⚠{m.NC} пустой ввод — ещё раз")
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"  {m.RED}✗{m.NC} невалидный JSON: {e}")
            continue
        if not isinstance(parsed, dict):
            print(f"  {m.RED}✗{m.NC} корень должен быть объектом {...}")
            continue
        print(f"  {m.GREEN}✓{m.NC} JSON принят")
        return parsed


def _hop_pattern_cfg(exit_node: dict) -> Optional[dict]:
    """trafficPattern хоп-ноги (Entry → Exit) для конкретного Exit.

    Приоритет: custom-JSON (hop_pattern) → именованный пресет (hop_preset)
    → legacy-фолбэк: пресет standalone-установки Entry (данные,
    сохранённые до per-Exit пресетов; на проде B/DE оба = basic).

    Рекомендация: держать паттерн хопа РАВНЫМ пресету mita на Exit.
    Живой тест 01.10 (B↔DE, medium/basic/disabled-матрица) показал,
    что mieru толерантен к рассинхрону (кадры self-describing, паттерн
    — косметика потока клиента: E2E OK во всех комбинациях), но
    совпадение даёт предсказуемую симметрию обфускации обеих ног."""
    m = _mieru()
    if exit_node.get("hop_pattern"):
        return exit_node["hop_pattern"]
    name = exit_node.get("hop_preset")
    if name and name in m._MIERU_TRAFFIC_PRESETS:
        return m._MIERU_TRAFFIC_PRESETS[name]["config"]
    return _traffic_pattern_cfg()



# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES-ДВИЖОК (единственный источник правил для live/routing.sh)
# ══════════════════════════════════════════════════════════════════════════════

def _active_exits(st: dict) -> list:
    """Exits, участвующие в правилах: enabled и не 'healthy=False'."""
    out = []
    for e in st.get("exits", []):
        if not e.get("enabled", True):
            continue
        if e.get("healthy") is False:
            continue
        out.append(e)
    return out


def _effective_pinned(st: dict, act: list) -> tuple:
    """Действующий закреплённый Exit с учётом fallback'а.

    Порт pinned-механики из dpi_detector (VLESS), фазы A/B:
      — закреплённый жив/включён → (он, None);
      — закреплённый мёртв/отключён → (первый живой по списку,
        id закреплённого) — фаза B, деградация;
        восстановление (фаза A) происходит само: как только
        закреплённый снова попадает в act, резолвер возвращает его;
      — пиннинг не задан → (None, None).
    Чистая функция: state не мутирует — и правила, и статус/меню
    разрешают одно и то же состояние одинаково."""
    pid = st.get("pinned_exit")
    if not pid:
        return None, None
    by_id = {e["id"]: e for e in act}
    pinned = by_id.get(pid)
    if pinned is not None:
        return pinned, None
    for e in act:            # фаза B: первый живой по порядку списка
        return e, pid
    return None, pid         # живых нет — правила трогать нечем


# ── СОСТАВ БАЛАНСИРОВКИ (lb_exits, порт awg_cascade_lb 06.10) ────────────────
#  Балансировка между ВЫБРАННЫМИ Exit-ами (пара/подмножество/все):
#  st['lb_exits'] = [id Exit-ов]; пусто = все (обратная совместимость).
#  Валидных (известных и включённых) <2 → фолбэк на все: одиночный
#  Exit молча — риск для трафика (зеркало AWG: «молчаливое выключение
#  LB запрещено»). Пиннинг (pinned_exit) ОРТОГОНАЛЕН составу: закреплён
#  вне состава — работает (явный override юзера, стратегии всё равно
#  не действуют); резолв пина — по полному активному списку.

def _normalize_lb_selection(exits: Optional[list],
                            all_exits: list) -> list:
    """IDs выбранных Exit-ов: уникальные, известные, в порядке st['exits']
    (правила не «прыгают» при другом порядке ввода). Токен = id Exit-а
    ИЛИ метка (метка неоднозначна — токен игнорируется). None/пусто → []
    (= все). Чистая функция (тестируется без сервера)."""
    if not exits:
        return []
    by_id = {e.get("id") for e in all_exits}
    label_ids: dict = {}
    for e in all_exits:
        lbl = e.get("label")
        if lbl:
            if lbl in label_ids:            # дубль метки — неоднозначно
                label_ids[lbl] = None
            else:
                label_ids[lbl] = e.get("id")
    wanted: list = []
    for x in exits:
        tok = (x or "").strip() if isinstance(x, str) else x
        if not tok:
            continue
        eid = tok if tok in by_id else label_ids.get(tok)
        if eid and eid not in wanted:
            wanted.append(eid)
    return [e["id"] for e in all_exits if e.get("id") in set(wanted)]


def _lb_effective_exits(st: dict, act: Optional[list] = None) -> list:
    """Активные Exit-ы, между которыми балансируем (lb_exits-фильтр).

    act — активные Exit-ы (по умолчанию _active_exits: enabled+healthy);
    выбор хранится в st['lb_exits'] (ids). Пусто = все; валидных
    (известных И включённых) <2 → фолбэк на все. Выбранный, но
    недоступный (healthy=False) просто выпадает из ротации — это
    естественная деградация, как и до выбора состава. Чистая функция."""
    if act is None:
        act = _active_exits(st)
    sel = _normalize_lb_selection(st.get("lb_exits"), st.get("exits", []))
    if not sel:
        return list(act)
    enabled_ids = {e["id"] for e in st.get("exits", [])
                   if e.get("enabled", True)}
    if sum(1 for x in sel if x in enabled_ids) < 2:
        return list(act)       # молчаливая одиночная нода запрещена
    return [e for e in act if e.get("id") in set(sel)]


def _lb_exits_summary(st: dict) -> str:
    """Строка состава для меню/статуса: 'de, pl1 (2 из 4)' / 'все (4)'."""
    exits = st.get("exits", [])
    sel = _normalize_lb_selection(st.get("lb_exits"), exits)
    if not sel:
        return f"все ({len(exits)})"
    labels = {e["id"]: (e.get("label") or e["id"]) for e in exits}
    eff = len(_lb_effective_exits(st))
    return f"{', '.join(labels[i] for i in sel if i in labels)} ({eff} из {len(exits)})"


# ══════════════════════════════════════════════════════════════════════════════
#  МЕТРИКИ ВЕСОВЫХ СТРАТЕГИЙ (порт smart_balancer VLESS, 01.10)
# ══════════════════════════════════════════════════════════════════════════════

def _count_exit_load(exit_node: dict) -> int:
    """Нагрузка Exit = established-соединения на его socks-порт
    (подключения redsocks → mieru-hop на 127.0.0.1). Аналог
    _probe_active_connections из smart_balancer (VLESS)."""
    sp = exit_node.get("socks_port")
    if not sp:
        return _B_NORM_LOAD
    r = _run(["ss", "-tnH", "state", "established"], capture=True)
    n = 0
    for line in (r.stdout or "").splitlines():
        cols = line.split()
        if len(cols) >= 4:
            # точное совпадение порта: :24081 не матчит :240818
            if cols[2].endswith(f":{sp}") or cols[3].endswith(f":{sp}"):
                n += 1
    return n


def _probe_exit_ttfb(exit_node: dict, timeout: float = 5.0) -> Optional[float]:
    """TTFB через socks-порт хопа (аналог _probe_bandwidth_ttfb из
    smart_balancer VLESS). Лёгкая проба: 204-эндпоинты по очереди.
    None = нет данных (как в VLESS — «худший» случай в score)."""
    sp = exit_node.get("socks_port")
    if not sp:
        return None
    for url in _TTFB_URLS:
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
                 "--max-time", str(int(timeout)),
                 "-x", f"socks5h://127.0.0.1:{sp}", url],
                capture_output=True, text=True, timeout=timeout + 2)
            t = (r.stdout or "").strip()
            if r.returncode == 0 and t:
                return round(float(t) * 1000.0, 1)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            continue
    return None


# EMA-сглаживание метрик: свежие пробы качаются (TTFB через
# CDN-хоп ±сотни мс, load скачкообразный) — мгновенные метрики качали
# доли ±10 п.п. на ровном месте, и каждый health-тик считал это
# «материальным дрейфом». Сглаживаем по истории st['metrics_ema'].
_B_EMA_ALPHA = 0.35          # вес свежей пробы (0..1]: меньше — глаже
_B_EMA_MAX_AGE_S = 900       # история старше 15 мин — протухла


def _ema_metrics(st: dict, lbl: str, fresh: dict) -> dict:
    """EMA-сглаживание метрик Exit-а (история в st['metrics_ema']).

    Единичные скачки проб не должны качать доли каскада: fresh
    смешивается с предыдущим сглаженным значением (α=0.35 — всплеск
    3x даёт сдвиг ~1.35x). Нет истории / протухла (>15 мин) / метрика
    не числовая — возвращаем fresh как есть (быстрый старт, прежняя
    семантика). Побочный эффект: пишет историю в st (сохранится
    ближайшим state_save)."""
    hist_all = st.setdefault("metrics_ema", {})
    hist = hist_all.get(lbl)
    out = dict(fresh)
    if isinstance(hist, dict):
        try:
            age = time.time() - float(hist.get("ts") or 0)
        except (TypeError, ValueError):
            age = -1.0
        if 0 <= age <= _B_EMA_MAX_AGE_S:
            for k, v in fresh.items():
                h = hist.get(k)
                if (isinstance(v, (int, float)) and not isinstance(v, bool)
                        and isinstance(h, (int, float))
                        and not isinstance(h, bool)):
                    out[k] = _B_EMA_ALPHA * v + (1 - _B_EMA_ALPHA) * h
    out["ts"] = time.time()
    hist_all[lbl] = out
    return {k: v for k, v in out.items() if k != "ts"}


def _balance_shares(st: dict, act: list) -> Optional[dict]:
    """Доли Exit-ов для весовых стратегий: label → q, Σq = 1.

      leastping: w ∝ 1/latency_ms   (health-пробы, 1 мин)
      leastload: w ∝ 1/(1+нагрузка) (established на socks-порту хопа)
      smart:     w ∝ 1/score, score = 0.5·норм(пинг) + 0.3·норм(TTFB)
                                          + 0.2·норм(нагрузка) — веса и
                 нормализация зеркально smart_balancer (VLESS)

    None для ядерных стратегий (rr/random/prio) — их распределяет
    iptables без пересчёта. Деградация всех метрик → равномерный
    фолбэк (как rr). Доли < 0.5% отсекаются, остаток перенормируется."""
    strategy = (st.get("strategy") or "rr").lower()
    if strategy not in METRIC_STRATEGIES or not act:
        return None
    metrics: dict = {}
    weights: dict = {}
    for e in act:
        lbl = e.get("label") or e["id"]
        lat = e.get("latency_ms")
        lat = float(lat) if lat is not None else None
        mm: dict = {"lat_ms": lat}
        if strategy in ("leastload", "smart"):
            mm["load"] = _count_exit_load(e)
        if strategy == "smart":
            mm["ttfb_ms"] = _probe_exit_ttfb(e)
        # EMA-сглаживание: всплеск пробы (TTFB CDN-хоп) не
        # должен качать доли — смешиваем с историей st['metrics_ema'].
        sm = _ema_metrics(st, lbl, mm)
        lat = sm.get("lat_ms")
        ttfb = sm.get("ttfb_ms")
        load = sm.get("load")
        load_v = load if isinstance(load, (int, float)) else 0
        if strategy == "leastping":
            w = (1.0 / max(lat, 1.0)) if lat is not None else 0.0
        elif strategy == "leastload":
            w = 1.0 / (1 + load_v)
        else:  # smart — composite score, зеркально _compute_score (VLESS)
            lat_n = min(1.0, (lat if lat is not None else _B_NORM_LAT_MS)
                        / _B_NORM_LAT_MS)
            ttfb_n = min(1.0, (ttfb if ttfb is not None else _B_NORM_TTFB_MS)
                         / _B_NORM_TTFB_MS)
            load_n = min(1.0, load_v / _B_NORM_LOAD)
            score = round(_B_W_LATENCY * lat_n + _B_W_BANDWIDTH * ttfb_n
                          + _B_W_LOAD * load_n, 4)
            sm["score"] = score
            w = 1.0 / max(score, _B_SCORE_FLOOR)
        metrics[lbl] = sm
        weights[lbl] = w
    total = sum(weights.values())
    if total <= 0:
        q = {lbl: 1.0 / len(act) for lbl in weights}
    else:
        q = {lbl: w / total for lbl, w in weights.items()}
    kept = {lbl: v for lbl, v in q.items() if v >= _B_SHARE_FLOOR}
    if kept and len(kept) < len(q):
        sk = sum(kept.values())
        q = {lbl: v / sk for lbl, v in kept.items()}
    return {"strategy": strategy, "ts": _ts(), "shares": q, "metrics": metrics}


def _metric_exit_specs(st: dict, M: list, act: list,
                       bal: Optional[dict]) -> list:
    """Правила весовых стратегий: weighted random по долям.

    Порядок Exit-ов — по убыванию доли (численно устойчивые
    вероятности). Правило i получает p_i = q_i / (1 − Σ_{j<i} q_j);
    последний (наименьшая доля) — catch-all без statistic. Все живые
    Exit-ы в ротации: агрегация каналов сохраняется (гигабит у
    клиента), метрика задаёт лишь веса."""
    specs: list = []
    if bal is None:
        return specs
    shares = bal.get("shares") or {}
    order = sorted(
        act,
        key=lambda e: (-shares.get(e.get("label") or e["id"], 0.0),
                       str(e.get("label") or e["id"])))
    # catch-all достаётся последнему из УЧАСТВУЮЩИХ (если последний по
    # порядку вылетел по floor/без порта — catch-all уходит не ему)
    kept = [e for e in order
            if e.get("redsocks_port")
            and shares.get(e.get("label") or e["id"], 0.0) >= _B_SHARE_FLOOR]
    tail = 0.0
    for i, e in enumerate(kept):
        rp = e.get("redsocks_port")
        lbl = e.get("label") or e["id"]
        q = shares.get(lbl, 0.0)
        rest = M + ["-p", "tcp"]
        if i < len(kept) - 1:
            p = q / max(1.0 - tail, 0.01)
            rest += ["-m", "statistic", "--mode", "random",
                     "--probability", _prob_str(p)]
        rest += ["-j", "REDIRECT", "--to-ports", str(rp)]
        specs.append({"table": "nat", "chain": "OUTPUT", "rest": rest})
        tail += q
    return specs


def _rule_specs(st: dict, bal: Optional[dict] = None) -> list:
    """Все правила каскада. Формат: {"table","chain","rest"}.

    rest — argv после `-A/-D <chain>`. Порядок в nat OUTPUT: guard, затем
    правила по Exit-ам. Добавляются В КОНЕЦ OUTPUT (-A) — после
    существующих правил Chimera (TG-REDIRECT и пр. сохраняют приоритет).

    Стратегии (порт smart_balancer VLESS, 01.10):
      rr        — statistic nth, равномерно по соединениям
      random    — statistic random, равномерно случайно на соединение
      prio      — active-backup: только первый живой Exit
      leastping — доли ∝ 1/пинга (health), weighted random
      leastload — доли ∝ 1/(1+нагрузка), weighted random
      smart     — доли ∝ 1/score (пинг+TTFB+нагрузка), weighted random ★
    Для весовых bal = _balance_shares(...) (проба load/TTFB на месте,
    если не передан); ядерным bal не нужен.
    """
    M = _matcher_args(st)
    specs = []
    if not M:
        return specs

    # guard: loopback-цели mita не заворачиваем (DNS на 127.0.0.1 и т.п.).
    # Фикс бага 01.10 (критический, E2E-обрыв): было «! -d 127.0.0.0/8» —
    # RETURN срабатывал на ВНЕШНЕМ трафике и каскад не работал вовсе.
    # Правильная семантика: RETURN только для целей В 127/8, остальное
    # идёт дальше к REDIRECT-правилам Exit-ов.
    specs.append({
        "table": "nat", "chain": "OUTPUT",
        "rest": M + ["-p", "tcp", "-d", "127.0.0.0/8", "-j", "RETURN"],
    })

    # b4-exempt (двухплечевой сплит, паритет с VLESS+B4): блок-лист
    # mieru_dpi → НАПРЯМУЮ с Entry (b4 дурит ТСПУ, цель видит RU-IP),
    # остальное — в Exit-ы; own-IP guard — сервисы самой ноды (DoH
    # cdn2.example:30443 и пр.) не гонять хэмпином через Exit
    if _b4_exempt_active(st):
        own = _b4_own_ip()
        if own:
            specs.append({
                "table": "nat", "chain": "OUTPUT",
                "rest": M + ["-p", "tcp", "-d", own,
                             "-m", "comment", "--comment", "mcs-b4-ownip",
                             "-j", "RETURN"],
            })
        specs.append({
            "table": "nat", "chain": "OUTPUT",
            "rest": M + ["-p", "tcp",
                         "-m", "set", "--match-set", _B4_IPSET, "dst",
                         "-m", "comment", "--comment", "mcs-b4-exempt",
                         "-j", "RETURN"],
        })

    act_all = _active_exits(st)
    # пин ортогонален составу: резолв закреплённого — по полному
    # активному списку (закреплён вне состава — работает, явный override)
    pin_eff, _fb = _effective_pinned(st, act_all)
    # стратегии балансировки — только ВЫБРАННЫЕ Exit-ы (lb_exits)
    act = _lb_effective_exits(st, act_all)
    strategy = (st.get("strategy") or "rr").lower()
    if strategy not in BALANCE_STRATEGIES:
        strategy = "rr"
    n = len(act)

    if pin_eff is not None:
        # pinned-режим (порт из VLESS): весь трафик → один Exit,
        # балансировщик выключен; при падении health-тик перестроит
        # правила на fallback-резолве (_effective_pinned, фаза B)
        rp = pin_eff.get("redsocks_port")
        if rp:
            specs.append({"table": "nat", "chain": "OUTPUT",
                          "rest": M + ["-p", "tcp",
                                       "-j", "REDIRECT",
                                       "--to-ports", str(rp)]})
    elif strategy in METRIC_STRATEGIES:
        specs.extend(_metric_exit_specs(st, M, act, bal))
    else:
        for i, e in enumerate(act):
            rp = e.get("redsocks_port")
            if not rp:
                continue
            rest = M + ["-p", "tcp"]
            if strategy == "rr" and i < n - 1:
                # классический round-robin: правило i срабатывает на каждом
                # (n-i)-м соединении, последнее — без statistic (остаток)
                rest += ["-m", "statistic", "--mode", "nth",
                         "--every", str(n - i), "--packet", "0"]
            elif strategy == "random" and i < n - 1:
                # равномерно случайно на соединение: p_i = 1/(n-i)
                rest += ["-m", "statistic", "--mode", "random",
                         "--probability", _prob_str(1.0 / (n - i))]
            elif strategy == "prio" and i > 0:
                continue  # active-backup: правила только для первого живого
            rest += ["-j", "REDIRECT", "--to-ports", str(rp)]
            specs.append({"table": "nat", "chain": "OUTPUT", "rest": rest})

    if st.get("strict_udp_block"):
        specs.append({
            "table": "filter", "chain": "OUTPUT",
            "rest": M + ["-p", "udp", "!", "-d", "127.0.0.0/8",
                         "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
        })
    return specs


def _spec_argv(spec: dict, add: bool) -> list:
    flag = "-A" if add else "-D"
    return ["iptables", "-t", spec["table"], flag, spec["chain"]] + spec["rest"]


# ══════════════════════════════════════════════════════════════════════════
#  СЕРИАЛИЗАЦИЯ ПРИМЕНЕНИЯ + СВЕРКА ЖИВЫХ ПРАВИЛ (фикс гонки 01.10)
#
#  Живой кейс на B: [P] в TUI и health-тик применяли правила
#  одновременно — state сохранил пин fi1 (REDIRECT 23084), ядро — пин
#  pl1 (23083); тик доверяет st['applied_rules'], рассинхрон жил бы
#  вечно. Лечение: (1) flock — тик и TUI-хендлеры не пересобирают
#  правила concurrently; (2) каждый тик сверяет живые правила с
#  applied_rules (iptables -S скан) и перестраивает при расхождении.
# ══════════════════════════════════════════════════════════════════════════

_LOCK_PATH = _MODULE_STATE.parent / "mieru_cascade.lock"


@contextlib.contextmanager
def _cascade_lock(wait_hint: bool = False):
    """flock-сериализация применений правил (TUI ↔ health-тик).

    Держатели: health_tick (всё тело — load → пробы → apply → save) и
    TUI-хендлеры ([S]/[P]/[4]/смена матчера/деактивация). flock
    освобождается ядром при смерти процесса — зависший TUI не
    заблокирует тик навсегда. wait_hint=True (TUI): если лок занят —
    подсказка юзеру, затем ожидание (типично 3-15 с). Недоступность
    lock-файла (нет прав — оффлайн-сьюты) — деградация без
    блокировки: в проде каталог state заведомо доступен (сам state
    лежит в нём), оффлайн-сьюты однопоточны."""
    fd = None
    try:
        _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        if wait_hint:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                print("  ⏳ ждём: параллельное применение правил "
                      "(health-тик)…")
                fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError:
        if fd is not None:
            os.close(fd)
        fd = None
    try:
        yield
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _live_cascade_rules(st: dict) -> Optional[dict]:
    """Живые правила каскада из `iptables -S` (таблица → argv-список,
    в порядке цепочки). None — скан не удался (правила наугад не
    трогаем). Парсинг зеркален _purge_orphan_rules: декавычивание -S
    (кавычки --path ломали сигнатурный поиск — бага 01.10)."""
    rps = set()
    for e in st.get("exits", []):
        rp = e.get("redsocks_port")
        if rp:
            rps.add(str(rp))
    sigs = [f"-m cgroup --path {_MITA_CGROUP}"]
    uid = _mita_uid()
    if uid is not None:
        sigs.append(f"-m owner --uid-owner {uid}")
    out: dict = {}
    for table in ("nat", "filter"):
        try:
            r = _run(["iptables", "-t", table, "-S", "OUTPUT"],
                     capture=True)
        except OSError:
            return None
        if r.returncode != 0:
            return None
        rows = []
        for raw_line in (r.stdout or "").splitlines():
            if not raw_line.startswith("-A OUTPUT "):
                continue
            line = raw_line.replace('"', "")
            if not any(s in line for s in sigs):
                continue
            argv = line[len("-A OUTPUT "):].split()
            ours = False
            for i, tok in enumerate(argv):
                if (tok == "--to-ports" and i + 1 < len(argv)
                        and argv[i + 1] in rps):
                    ours = True
                    break
            if not ours and "127.0.0.0/8" in argv and "RETURN" in argv:
                ours = True
            if not ours and ("mcs-b4-exempt" in argv
                             or "mcs-b4-ownip" in argv):
                ours = True
            if (not ours and "REJECT" in argv
                    and "icmp-port-unreachable" in argv):
                ours = True
            if ours:
                rows.append(argv)
        out[table] = rows
    return out


def _rules_in_sync(st: dict) -> Optional[bool]:
    """Живые правила == st['applied_rules']?

    True/False — сверка выполнена; None — iptables -S не ответил.
    Двухступенчато (ядро печатает -S в КАНОНИЧЕСКОМ порядке — -d/-p до
    матчеров, наш argv другой; токен-в-токен сравнение давало ложный
    рассинхрон на каждом правиле — поймано первой живой сверкой на B):
      1) счёт: живых правил каскада ровно столько, сколько в applied
         (лишние сироты / потерянные ловятся расхождением количества);
      2) наличие: каждый спек — iptables -C (структурная проверка ядра,
         тот же матчинг, что у -D в _rules_apply; вероятности ядро
         сравнивает численно — float32-печать -S не мешает).
    Ловит: потерянные/лишние правила (сбой apply, ручные правки,
    частичный flush), чужие вероятности, подмену порта (живой кейс
    01.10: пин pl1 в ядре против пина fi1 в state)."""
    applied = st.get("applied_rules") or []
    live = _live_cascade_rules(st)
    if live is None:
        return None
    if sum(len(v) for v in live.values()) != len(applied):
        return False
    for sp in applied:
        if not proto_ipt_rule_exists(sp["table"], sp["chain"],
                                     sp["rest"]):
            return False
    return True


def _rules_apply(st: dict) -> bool:
    """Пересобирает правила каскада атомарно:
       0) удалить ТОЧНЫЕ ранее применённые (st['applied_rules'] —
          вероятности весовых стратегий неперечислимы, только replay);
       1) удалить legacy-варианты (смена стратегии/strict_udp/матчера);
       2) добить сироты по сигнатуре (iptables -S скан — любые
          поколения весов, включая чуждые этому запуску);
       3) добавить актуальные (весовые — со свежими пробами метрик);
       4) запомнить применённое в st['applied_rules'] и персистить
          (survive ребута: rules.v4 вернёт ровно этот набор, а
          routing.sh и health-тик будут знать точный набор для -D)."""
    act = _lb_effective_exits(st)   # доли/пробы — только выбранные
    pinned_now = bool(st.get("pinned_exit"))
    bal = (_balance_shares(st, act)
           if (st.get("strategy") or "").lower() in METRIC_STRATEGIES
           and not pinned_now else None)
    specs = _rule_specs(st, bal)

    # 0) точные прежние
    for sp in st.get("applied_rules") or []:
        while True:
            r = _run(_spec_argv(sp, add=False), capture=True)
            if r.returncode != 0:
                break
    # 1) legacy-перечисление (старый набор мог отличаться)
    for sp in _rule_specs_all_variants(st):
        while True:
            r = _run(_spec_argv(sp, add=False), capture=True)
            if r.returncode != 0:
                break
    # 2) сироты по сигнатуре
    _purge_orphan_rules(st)
    # 3) добавить текущие
    ok = True
    for sp in specs:
        r = _run(_spec_argv(sp, add=True), capture=True)
        if r.returncode != 0:
            print(f"  [!] iptables: {r.stderr.strip()[:200] if r.stderr else '?'}")
            ok = False
    # 4) запомнить + персист
    st["applied_rules"] = specs
    st["balance"] = bal
    st["weights_applied_ts"] = time.time()   # cooldown весовых ребалансов
    proto_ipt_persist()
    state_save(st)
    return ok


def _purge_orphan_rules(st: dict) -> None:
    """Добить сироты по сигнатуре (iptables -S скан, nat+filter OUTPUT).

    Ловит ЛЮБЫЕ наши правила прошлых поколений — взвешенные
    вероятности неперечислимы, поэтому сигнатура: матчер каскада
    (cgroup mita.service | owner uid=mita) + (REDIRECT на наш
    redsocks-порт | guard RETURN 127/8 | REJECT strict-udp).
    Чужие правила Chimera таких сочетаний не содержат."""
    rps = set()
    for e in st.get("exits", []):
        rp = e.get("redsocks_port")
        if rp:
            rps.add(str(rp))
    sigs = [f"-m cgroup --path {_MITA_CGROUP}"]
    uid = _mita_uid()
    if uid is not None:
        sigs.append(f"-m owner --uid-owner {uid}")
    for table in ("nat", "filter"):
        r = _run(["iptables", "-t", table, "-S", "OUTPUT"], capture=True)
        if r.returncode != 0:
            continue
        for raw_line in (r.stdout or "").splitlines():
            if not raw_line.startswith("-A OUTPUT "):
                continue
            # iptables -S печатает строковые значения В КАВЫЧКАХ
            # (--path "system.slice/mita.service"). Кавычки ломают и
            # сигнатурный поиск, и -D («rule not found») — баг 01.10:
            # взвешенные правила прошлых поколений переживали все
            # зачистки. Декавычиваем строку ДО всех проверок (кавычки
            # в значениях наших правил не встречаются).
            line = raw_line.replace('"', "")
            if not any(s in line for s in sigs):
                continue
            argv = line[len("-A OUTPUT "):].split()
            ours = False
            for i, tok in enumerate(argv):
                if (tok == "--to-ports" and i + 1 < len(argv)
                        and argv[i + 1] in rps):
                    ours = True
                    break
            if not ours and "127.0.0.0/8" in argv and "RETURN" in argv:
                ours = True
            if not ours and ("mcs-b4-exempt" in argv
                             or "mcs-b4-ownip" in argv):
                ours = True
            if (not ours and "REJECT" in argv
                    and "icmp-port-unreachable" in argv):
                ours = True
            if ours:
                _run(["iptables", "-t", table, "-D", "OUTPUT"] + argv,
                     capture=True)


def _rule_specs_all_variants(st: dict) -> list:
    """Спеки для зачистки: текущие + РАНЕЕ ВОЗМОЖНЫЕ (вкл/выкл strict_udp,
    обе стратегии) — чтобы после смены настроек не осталось хвостов."""
    out = []
    seen = set()

    def _add(sp):
        key = (sp["table"], sp["chain"], tuple(sp["rest"]))
        if key not in seen:
            seen.add(key)
            out.append(sp)

    M = _matcher_args(st)
    if M:
        _add({"table": "nat", "chain": "OUTPUT",
              "rest": M + ["-p", "tcp", "-d", "127.0.0.0/8", "-j", "RETURN"]})
        # legacy-вариант guard с инвертированным «!» (критический баг 01.10:
        # RETURN на внешнем трафике рвал весь каскад) — остаётся в зачистке,
        # чтобы после обновления модуля не осталось хвостов
        _add({"table": "nat", "chain": "OUTPUT",
              "rest": M + ["-p", "tcp", "!", "-d", "127.0.0.0/8",
                           "-j", "RETURN"]})
        # b4-exempt-поколения: set-правило перечислимо (статичный argv);
        # own-IP динамический — ловится applied_rules-реплеем и
        # сигнатурой mcs-b4-ownip в _purge_orphan_rules
        _add({"table": "nat", "chain": "OUTPUT",
              "rest": M + ["-p", "tcp",
                           "-m", "set", "--match-set", _B4_IPSET, "dst",
                           "-m", "comment", "--comment", "mcs-b4-exempt",
                           "-j", "RETURN"]})
        for e in st.get("exits", []):
            rp = e.get("redsocks_port")
            if not rp:
                continue
            # перечислимые варианты (смена стратегии/числа Exit-ов);
            # взвешенные вероятимости неперечислимы — их ловят
            # st['applied_rules'] (точный replay) и _purge_orphan_rules
            extras: list = [[]]
            for k in range(2, 9):    # rr: nth every 2..8
                extras.append(["-m", "statistic", "--mode", "nth",
                               "--every", str(k), "--packet", "0"])
            for k in range(2, 9):    # random: равномерно 1/k, k=2..8
                extras.append(["-m", "statistic", "--mode", "random",
                               "--probability", _prob_str(1.0 / k)])
            for extra in extras:
                _add({"table": "nat", "chain": "OUTPUT",
                      "rest": M + ["-p", "tcp"] + extra +
                      ["-j", "REDIRECT", "--to-ports", str(rp)]})
        _add({"table": "filter", "chain": "OUTPUT",
              "rest": M + ["-p", "udp", "!", "-d", "127.0.0.0/8",
                           "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]})
    return out


def _routing_sh_text(st: dict) -> str:
    """bash-скрипт пересборки правил при ребуте.

    Единственный источник истины — st['applied_rules'] (точный набор
    последнего apply, включая вероятности весовых стратегий — они
    неперечислимы). Replay: удалить точные → удалить legacy-варианты →
    добавить точные. Свежие пробы здесь НЕ нужны (и опасны на раннем
    буте): правила восстанавливаются 1-в-1, следующий health-тик
    (≤1 мин) пересчитает веса и при дрейфе перестроит."""
    applied = st.get("applied_rules") or []
    if not applied:
        # стейт до-нового формата: сгенерить из текущих настроек
        try:
            applied = _rule_specs(st)
        except Exception:
            applied = []
    lines = [
        "#!/bin/bash",
        "# mieru-cascade routing — регенерируется mieru_cascade.py при каждом apply",
        "# 0) удалить ТОЧНЫЕ правила последнего apply (веса/вероятности",
        "#    неперечислимы — только точный replay по applied_rules)",
    ]
    # ipset блок-листа ДО правил: -m set требует существующий set. После
    # ребута набор пуст до первого health-тика (≤1 мин мягкой деградации:
    # блок-лист уедет в каскад, не сломается).
    lines.append("ipset create " + _B4_IPSET +
                 " hash:ip maxelem 65536 -exist 2>/dev/null || true")
    for sp in applied:
        argv = _spec_argv(sp, add=False)
        lines.append("while " + " ".join(argv) +
                     " 2>/dev/null; do :; done")
    lines.append("# 1) зачистка legacy-вариантов (идемпотентно; restore из")
    lines.append("#    rules.v4 мог вернуть старый набор после смены стратегии)")
    for sp in _rule_specs_all_variants(st):
        argv = _spec_argv(sp, add=False)
        lines.append("while " + " ".join(argv) +
                     " 2>/dev/null; do :; done")
    lines.append("# 2) добавить актуальные — точный replay применённого")
    for sp in applied:
        argv = " ".join(_spec_argv(sp, add=True))
        lines.append(argv + " || echo \"mieru-cascade: WARN: правило не добавлено\"")
    lines.append('echo "mieru-cascade routing applied (matcher=' +
                 str(st.get("matcher")) +
                 ', strategy=' + str(st.get("strategy")) + ')"')
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
#  PORT_REGISTRY: выделение loopback-портов (проверка занятости)
# ══════════════════════════════════════════════════════════════════════════════

def _alloc_ports_for_exit(st: dict, label: str) -> Optional[dict]:
    """Выделяет 4 loopback-порта для нового Exit (socks/redsocks/rpc/http).

    Каждый порт проходит port_register() БЕЗ force → проверка занятости:
    реестр (чужой сервис) + ss-слушатели + ufw + /etc/services. Конфликт
    hybrid_addon:1080 и прочих ловится здесь. Окна по 50 на тип.
    """
    taken = {e.get(k) for e in st.get("exits", [])
             for k in ("socks_port", "redsocks_port", "rpc_port", "http_port")}

    def _find(base: int, top: int, kind: str) -> Optional[int]:
        for p in range(base, top + 1):
            if p in taken:
                continue
            ok, msg = port_register(
                SERVICE_MIERU_CASCADE, p, "tcp",
                comment=f"mieru-cascade {label} {kind} (loopback)")
            if ok:
                return p
            print(f"  [i] порт {p}/{kind} занят: {msg} — следующий")
        return None

    socks = _find(_SOCKS_BASE, _SOCKS_MAX, "socks5")
    reds = _find(_REDSOCKS_BASE, _REDSOCKS_MAX, "redsocks")
    rpc = _find(_RPC_BASE, _RPC_MAX, "rpc")
    http = _find(_HTTP_BASE, _HTTP_MAX, "http")
    if not (socks and reds and rpc and http):
        # откат частичной регистрации
        for p in (socks, reds, rpc, http):
            if p:
                port_unregister(SERVICE_MIERU_CASCADE, port=p)
        return None
    return {"socks_port": socks, "redsocks_port": reds,
            "rpc_port": rpc, "http_port": http}


def _release_ports_of_exit(exit_node: dict) -> None:
    for kind in ("socks_port", "redsocks_port", "rpc_port", "http_port"):
        p = exit_node.get(kind)
        if not p:
            continue
        ufw_close_port(p, "tcp", SERVICE_MIERU_CASCADE)   # чужие не трогает
        port_unregister(SERVICE_MIERU_CASCADE, port=p)


# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА ЗАВИСИМОСТЕЙ (download manager + честные fallback)
# ══════════════════════════════════════════════════════════════════════════════

def _redsocks_path() -> Optional[str]:
    return shutil.which("redsocks")


def _redsocks_comment_dnstc(text: str) -> str:
    """Комментирует блок dnstc {...} в конфиге redsocks (C-комментарий).

    Чистая функция (без ФС) — тестируется юнит-тестами. Debian-пакет
    redsocks ships дефолтный /etc/redsocks.conf с dnstc — «fake DNS
    server», слушающим 127.0.0.1:5300. Этот порт — upstream dnscrypt-proxy
    (AdGuard Home) во всех установках Chimera: коллизия = crash-loop
    dnscrypt после ребута (инцидент 2026-10-03, нода 203.0.113.103,
    3.8k рестартов, мёртвый DNS всей ноды). Каскаду dnstc не нужен —
    entry-сторона работает через собственные конфиги в /etc/mieru-cascade/.

    Идемпотентна: файл с уже установленным маркером возвращается
    без изменений (C-комментарии НЕ вкладываются — повторный wrap
    раскомментировал бы блок обратно).
    """
    if "/* chimera: dnstc disabled" in text:
        return text
    out: list = []
    depth = 0
    started = False
    for line in text.splitlines(keepends=True):
        if not started and re.match(r"\s*dnstc\s*\{", line):
            out.append("/* chimera: dnstc disabled — fake-DNS на :5300 "
                       "конфликтует с dnscrypt-proxy (инцидент 2026-10-03)\n")
            out.append(line)
            depth = line.count("{") - line.count("}")
            started = True
            if depth <= 0:
                out.append("*/\n")
                started = False
            continue
        if started:
            out.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                out.append("*/\n")
                started = False
            continue
        out.append(line)
    return "".join(out)


def _neutralize_system_redsocks() -> bool:
    """Гасит СИСТЕМНЫЙ redsocks.service и dnstc-блок в /etc/redsocks.conf.

    Debian-пакет redsocks (ставится _install_redsocks как зависимость
    каскада) не только кладёт конфиг с dnstc:5300, но и включает
    redsocks.service в автозагрузку (deb-systemd-helper). Пока dnscrypt
    жив, dnstc молча не биндится (сервис в failed), но после ребута
    юниты стартуют гонкой — если системный redsocks первым займёт
    :5300, dnscrypt-proxy уходит в crash-loop (bind: address already
    in use) и DNS сервера мёртв до ручного вмешательства.

    Каскаду системный инстанс НЕ нужен: каждому Exit-у соответствует
    свой mieru-cascade-redsocks@<id>.service с конфигом в
    /etc/mieru-cascade/redsocks-<id>.conf. Нейтрализация идемпотентна,
    выполняется на каждом apply и безопасна при любом состоянии.
    """
    # 1) dnstc-блок в дефолтном конфиге пакета → C-комментарий
    #    (маркер-гвардр: повторный wrap не вкладывается — иначе */
    #    раскомментировал бы блок обратно)
    try:
        if _REDSOCKS_CONF.exists():
            text = _REDSOCKS_CONF.read_text(encoding="utf-8", errors="replace")
            if "/* chimera: dnstc disabled" not in text and \
                    re.search(r"(?m)^\s*dnstc\s*\{", text):
                _REDSOCKS_CONF.write_text(_redsocks_comment_dnstc(text),
                                          encoding="utf-8")
                print("  [i] redsocks: dnstc-блок (:5300) нейтрализован в "
                      "/etc/redsocks.conf — конфликт с dnscrypt-proxy")
    except OSError as e:
        # конфиг недоступен — не блокируем установку, но честно предупреждаем
        print(f"  [!] redsocks: /etc/redsocks.conf: {e}")
    # 2) системный юнит: stop + disable + reset-failed.
    #    ТОЛЬКО plain «redsocks.service» — @-шаблоны mieru-cascade-redsocks@
    #    не трогаем (это рабочие инстансы каскада).
    if shutil.which("systemctl"):
        _run(["systemctl", "stop", "redsocks.service"], capture=True)
        _run(["systemctl", "disable", "redsocks.service"], capture=True)
        _run(["systemctl", "reset-failed", "redsocks.service"], capture=True)
    return True


def _install_redsocks() -> bool:
    """redsocks через download manager (.deb из пула дистрибутива).

    Основной путь — PackageSpec (mieru_cascade_packages.py): ручное
    размещение /root → зеркала (yandex/ubuntu) → post_install dpkg -i.
    Fallback (все зеркала упали): apt-get с честным warn — это отступление
    от DM, но лучше работающий модуль, чем отказ установки.

    после установки (и при уже установленном бинарнике)
    нейтрализуется СИСТЕМНЫЙ redsocks.service + dnstc-блок дефолтного
    /etc/redsocks.conf (fake-DNS :5300 = порт dnscrypt-proxy; пакет
    включает сервис в автозагрузку → после ребута гонка за :5300 →
    crash-loop dnscrypt → мёртвый DNS ноды; инцидент 2026-10-03).
    """
    if not _redsocks_path():
        from chimera.modules.download_manager import fetch_package
        from chimera.modules.mieru_cascade_packages import (
            redsocks_candidates, redsocks_spec_for,
        )
        installed = False
        for fn in redsocks_candidates():
            spec = redsocks_spec_for(fn)
            if fetch_package(spec, print_hint_on_failure=False,
                             progress_label="redsocks"):
                if _redsocks_path():
                    installed = True
                    break
        if not installed:
            print("  [!] redsocks: зеркала DM не ответили — fallback apt-get "
                  "(вне download manager)")
            _run(["apt-get", "install", "-y", "redsocks"],
                 capture=True, timeout=180)
    if not _redsocks_path():
        return False
    # обе ветки (свежая установка и уже установленный ранее пакет):
    # мина могла быть взведена задолго до этого apply — гасим всегда
    _neutralize_system_redsocks()
    return True


def _ensure_mieru_client() -> bool:
    """На Entry нужен mieru-клиент (в standalone-установке он опционален).

    Фикс бага деплоя 01.10 (live B): MIERU_TARGZ_SPEC.filename_builder
    требует version/arch — вызов fetch_package без kwargs падал с
    TypeError '<lambda>() missing 2 required positional arguments'.
    Версия — из state standalone-установки (записана при install),
    иначе latest с GitHub API (паттерн mieru._run_install).
    """
    m = _mieru()
    if m._MIERU_BIN.exists():
        return True
    # proto_get_latest_version — из proto_common (баг деплоя 01.10:
    # импорт из download_manager падал ImportError на прод-серверах)
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.mieru_packages import MIERU_TARGZ_SPEC

    mst = proto_load_state(m._MODULE_STATE)
    version = str(mst.get("version") or "").lstrip("vV")
    if not version:
        try:
            version = proto_get_latest_version(m._GITHUB_API, strip_v=True)
        except Exception:
            version = "unknown"
    if version in ("", "unknown"):
        version = "3.33.0"        # тот же fallback, что в mieru._run_install
    arch = "amd64" if m._is_amd64() else "arm64"
    try:
        ok = fetch_package(MIERU_TARGZ_SPEC, print_hint_on_failure=False,
                           progress_label="mieru-клиент",
                           version=version, arch=arch)
    except TypeError as e:
        print(f"  [!] mieru-клиент: fetch_package: {e}")
        return False
    return ok and m._MIERU_BIN.exists()


def _traffic_pattern_cfg() -> Optional[dict]:
    """Пресет обфускации standalone-установки Entry — той же формой,
    что mieru_dpi._e2e_probe (для hop-ноги через RU-границу)."""
    m = _mieru()
    try:
        st = proto_load_state(m._MODULE_STATE)
        preset = st.get("traffic_preset", "basic")
        if preset and preset != "disabled":
            return m._MIERU_TRAFFIC_PRESETS.get(preset, {}).get("config")
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD-ЮНИТЫ
# ══════════════════════════════════════════════════════════════════════════════

def _write_units() -> None:
    m = _mieru()
    # mieru start — само-форк в фон (демон), у клиента НЕТ команды `proxy`
    # (баг деплоя 01.10, live B). Юнит: oneshot + RemainAfterExit + ExecStop;
    # смерть форк-ребёнка systemd не видит — лечит health-timer
    # (_ensure_local_services: проба 127.0.0.1:socks_port → restart).
    _UNIT_HOP.write_text(
        "[Unit]\n"
        "Description=Mieru cascade hop client %i (Entry→Exit)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "Environment=HOME=/var/lib/mieru-cascade/%i\n"
        "Environment=XDG_CONFIG_HOME=/var/lib/mieru-cascade/%i/.config\n"
        f"ExecStart={m._MIERU_BIN} start\n"
        f"ExecStop={m._MIERU_BIN} stop\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    reds = _redsocks_path() or "/usr/sbin/redsocks"
    _UNIT_REDSOCKS.write_text(
        "[Unit]\n"
        "Description=Mieru cascade redsocks %i (transparent→SOCKS5)\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={reds} -c /etc/mieru-cascade/redsocks-%i.conf\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _UNIT_ROUTING.write_text(
        "[Unit]\n"
        "Description=Mieru cascade routing (iptables reapply at boot)\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/etc/mieru-cascade/routing.sh\n"
        "RemainAfterExit=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _UNIT_HEALTH.write_text(
        "[Unit]\n"
        "Description=Mieru cascade health check + rebalance\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={_HEALTH_WRAPPER}\n"
    )
    _UNIT_HEALTH_T.write_text(
        "[Unit]\n"
        "Description=Mieru cascade health timer\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=*:0/1\n"
        "AccuracySec=10s\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    _HEALTH_WRAPPER.write_text(_health_wrapper_text())
    _HEALTH_WRAPPER.chmod(0o755)
    _run(["systemctl", "daemon-reload"])


def _health_wrapper_text() -> str:
    """PYTHONPATH-safe wrapper (паттерн v5.1 из awg_cascade: cron/timer
    запускается с произвольной cwd — bare python -c падает с
    ModuleNotFoundError; wrapper экспортирует PYTHONPATH)."""
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            installer_path = str(
                Path(list(spec.submodule_search_locations)[0]).parent)
        else:
            installer_path = "/opt/chimera"
    except Exception:
        installer_path = "/opt/chimera"
    return (
        "#!/bin/bash\n"
        "# mieru-cascade health wrapper (PYTHONPATH-safe, паттерн v5.1)\n"
        f"export PYTHONPATH=\"{installer_path}:$PYTHONPATH\"\n"
        "/usr/bin/python3 -c \"\n"
        "import sys\n"
        f"sys.path.insert(0, '{installer_path}')\n"
        "from chimera.modules.mieru_cascade import health_tick_cli\n"
        "health_tick_cli()\n"
        "\" 2>&1 | logger -t mieru-cascade-health\n"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  ПРИМЕНИТЬ ВСЁ (Entry): конфиги + юниты + правила
# ══════════════════════════════════════════════════════════════════════════════

def _apply_all(st: dict) -> bool:
    """Полный apply Entry-стороны. Вызывается после любого изменения."""
    m = _mieru()
    if not m._MITA_BIN.exists():
        print("  [!] standalone-Mieru не установлен (нужен для Entry)")
        return False
    if not _ensure_mieru_client():
        print("  [!] mieru-клиент недоступен (download manager не смог)")
        return False
    if not _install_redsocks():
        print("  [!] redsocks не установлен")
        return False

    _ETC_DIR.mkdir(parents=True, exist_ok=True)
    _INST_DIR.mkdir(parents=True, exist_ok=True)

    # 1) порты: выделить недостающим (однократно; свои — реюз)
    for e in st.get("exits", []):
        if not e.get("socks_port"):
            ports = _alloc_ports_for_exit(st, e.get("label", e["id"]))
            if not ports:
                print(f"  [!] не удалось выделить порты для {e['label']}")
                return False
            e.update(ports)

    # 2) конфиги инстансов + redsocks (паттерн обфускации — per-Exit,
    #    _hop_pattern_cfg: custom hop_pattern → hop_preset → legacy-фолбэк)
    _write_units()
    for e in st.get("exits", []):
        _seed_hop_instance(e, _hop_pattern_cfg(e))
        (_ETC_DIR / f"redsocks-{e['id']}.conf").write_text(_redsocks_conf(e))

    # ipset блок-листа ДО правил: -m set требует существующий set
    # (пустой до первого refresh — miss = каскад, мягкая деградация)
    if _b4_exempt_active(st):
        _b4set_ensure()

    # 3+4) правила + сервисы + персист — под локом (сериализация с
    # health-тиком, фикс гонки 01.10): state_save обязан попасть в ту
    # же критическую секцию, что и _rules_apply
    with _cascade_lock(wait_hint=True):
        ok_rules = _rules_apply(st)
        _ROUTING_SH.write_text(_routing_sh_text(st))
        _ROUTING_SH.chmod(0o755)

        # сервисы
        for e in st.get("exits", []):
            for unit in (f"mieru-hop@{e['id']}",
                         f"mieru-cascade-redsocks@{e['id']}"):
                _run(["systemctl", "enable", unit])
                _run(["systemctl", "restart", unit])
        for unit in ("mieru-cascade-routing", "mieru-cascade-health.timer"):
            _run(["systemctl", "enable", unit])
            _run(["systemctl", "restart", unit])

        state_save(st)

    # вне лока: резолв доменов блок-листа (сеть, ~10-25с) — правила
    # уже смотрят на set; освежать можно и из health-тика
    if _b4_exempt_active(st):
        _b4set_refresh(st)
    return ok_rules


# ══════════════════════════════════════════════════════════════════════════════
#  НАСТРОЙКА РОЛЕЙ
# ══════════════════════════════════════════════════════════════════════════════

def _strategy_desc() -> dict:
    """Короткие описания стратегий (единый источник для [S] и [1])."""
    return {
        "rr": "round-robin по соединениям (ядро iptables)",
        "random": "равномерно случайно на соединение (ядро)",
        "prio": "active-backup: только первый живой Exit",
        "leastping": "доли ∝ 1/пинг (пересчёт каждую минуту)",
        "leastload": "доли ∝ 1/(1+соединения на хопе)",
        "smart": "score: пинг+TTFB+нагрузка — как VLESS",
    }


def _box_strategy_items(m, current: str) -> None:
    """Список стратегий внутри бокса — [S] меню каскада и [1] настройка
    Entry. ● = текущая, ★ = рекомендованная. Строки подогнаны под
    _BOX_W=66 (с запасом ~10 колонок на маркеры)."""
    desc = _strategy_desc()
    for i, k in enumerate(BALANCE_STRATEGIES, 1):
        mark = (f" {m.GREEN}●{m.NC}" if k == current else "") + \
               (f" {m.GREEN}★{m.NC}" if k == "smart" else "")
        m._box_item(str(i),
                    f"{m.BOLD}{k}{m.NC}{mark} {m.DIM}— {desc[k]}{m.NC}")
    m._box_row(f"  {m.DIM}● текущая    ★ рекомендованная (как VLESS){m.NC}")


def _setup_entry(st: dict) -> None:
    m = _mieru()
    m._box_top("⬇  ENTRY  •  вход каскада (RU)")
    m._box_row()
    m._box_info("Этот сервер принимает клиентов (standalone-Mieru) и")
    m._box_info("заворачивает исходящий трафик mita через Exit-ноды.")
    m._box_row()
    if not m._is_installed():
        m._box_warn("Сначала установите standalone-Mieru (меню Mieru → [1]).")
        m._box_bot(); m._pause(); return
    m._box_bot(); print()

    # стратегия (порт из smart_balancer VLESS + ядерные rr/prio)
    m._box_top("⚖  Балансировка Exit-ов")
    m._box_row()
    _box_strategy_items(m, (st.get("strategy") or "rr").lower())
    m._box_row(f"  {m.DIM}весовые (4-6): все живые Exit-ы в ротации —{m.NC}")
    m._box_row(f"  {m.DIM}агрегация каналов сохраняется{m.NC}")
    m._box_row()
    m._box_bot(); print()
    raw = proto_ask(f"  {m.CYAN}Выбор [Enter=rr]: {m.NC}",
                    default="rr", c=True).strip().lower()
    by_num = {"1": "rr", "2": "random", "3": "prio",
              "4": "leastping", "5": "leastload", "6": "smart"}
    strategy = by_num.get(raw, raw)
    if strategy not in BALANCE_STRATEGIES:
        strategy = "rr"

    raw = proto_ask(
        f"  {m.CYAN}Блокировать UDP-нагрузку mita (strict)? [y/N]: {m.NC}",
        default="N", c=True).strip().lower()
    strict = raw in ("y", "yes", "д", "да")

    # матчинг процесса mita
    if _probe_cgroup():
        matcher = "cgroup"
        print(f"  {m.GREEN}✓{m.NC} матчинг: cgroup (system.slice/mita.service)")
    else:
        print(f"  {m.YELLOW}⚠{m.NC} cgroup не поддерживается — fallback owner")
        if not _apply_owner_dropin():
            print(f"  {m.RED}✗{m.NC} не удалось перевести mita на юзера mita")
            m._pause(); return
        matcher = "owner"
        print(f"  {m.GREEN}✓{m.NC} матчинг: owner uid=mita (drop-in применён)")

    old = st.get("matcher")
    st.update({"role": "entry", "strategy": strategy,
               "strict_udp_block": strict, "matcher": matcher})
    with _cascade_lock(wait_hint=True):
        state_save(st)
        if old and old != matcher:
            # смена матчера: зачистить правила старого режима
            _rules_apply(st)

    m._box_top("✅  ENTRY НАСТРОЕН")
    m._box_row()
    m._box_kv("Матчинг:", matcher)
    m._box_kv("Стратегия:", strategy)
    m._box_kv("Strict UDP:", "да" if strict else "нет (UDP идёт напрямую с Entry)")
    m._box_row()
    m._box_info("Дальше: [3] Управление Exit-нодами → добавить Exit-ы")
    m._box_info("затем [4] Применить.")
    m._box_bot()
    m._pause()


def _setup_exit(st: dict) -> None:
    m = _mieru()
    m._box_top("⬆  EXIT  •  выход каскада (EU)")
    m._box_row()
    m._box_info("Этот сервер — зарубежный exit. Нужен standalone-Mieru")
    m._box_info("и hop-пользователь для подключения Entry.")
    m._box_row()
    if not m._is_installed():
        m._box_warn("Standalone-Mieru не установлен.")
        raw = proto_ask("  Установить сейчас? [y/N]: ", default="N", c=True).strip().lower()
        if raw not in ("y", "yes", "д", "да"):
            return
        m._run_install()
        if not m._is_installed():
            m._box_err("Установка не удалась"); m._pause(); return
    m._box_bot(); print()

    mst = proto_load_state(m._MODULE_STATE)
    users = mst.get("users", [])
    username = proto_ask(
        f"  {m.CYAN}Имя hop-пользователя [{DEFAULT_HOP_USERNAME}]: {m.NC}",
        default=DEFAULT_HOP_USERNAME, c=True).strip()
    if not m._RE_USERNAME.match(username):
        print(f"  {m.RED}✗{m.NC} недопустимое имя"); m._pause(); return
    if any(u.get("username") == username for u in users):
        print(f"  {m.RED}✗{m.NC} уже существует (удалите в [2] или новое имя)")
        m._pause(); return
    raw_pass = proto_ask(f"  {m.CYAN}Пароль (Enter=авто): {m.NC}", default="", c=True).strip()
    password = raw_pass or proto_gen_password()

    # обфускация СЕРВЕРА (mita на этом Exit) — паритет с аддоном:
    # выбор при установке, а не только потом в «Пресеты обфускации».
    # Паттерн виден в итоговой рамке — его же выбрать на Entry для хопа.
    cur_tp = mst.get("traffic_preset", "basic")
    tp_name, tp_custom = _ask_pattern_menu(m, current=cur_tp,
                                           subject="mita на Exit")
    if tp_name == "custom" and tp_custom is None:
        tp_name, tp_custom = cur_tp, None

    users.append({"username": username, "password": password})
    mst["users"] = users

    cfg_dict = (tp_custom if tp_name == "custom"
                else m._MIERU_TRAFFIC_PRESETS.get(tp_name, {}).get("config"))
    cfg = m._build_server_config(
        users,
        mst.get("port_start", m._DEFAULT_PORT_START),
        mst.get("port_end", m._DEFAULT_PORT_END),
        mst.get("protocol", m._DEFAULT_PROTOCOL),
        traffic_pattern=cfg_dict,
    )
    err = m._apply_server_config(cfg)
    if err:
        print(f"  {m.RED}✗{m.NC} mita apply config: {err[:200]}"); m._pause(); return
    mst["traffic_preset"] = tp_name
    if tp_name == "custom":
        mst["traffic_pattern_custom"] = tp_custom
    else:
        mst.pop("traffic_pattern_custom", None)
    proto_save_state(m._MODULE_STATE, mst)
    # trafficPattern не поддерживает hot-reload — restart (не reload)
    _run(["systemctl", "restart", m._SERVICE_NAME])

    st["role"] = "exit"
    st["exit"] = {
        "hop_username": username, "hop_password": password,
        "port_start": mst.get("port_start", m._DEFAULT_PORT_START),
        "port_end": mst.get("port_end", m._DEFAULT_PORT_END),
        "protocol": mst.get("protocol", m._DEFAULT_PROTOCOL),
        "traffic_preset": tp_name,
    }
    state_save(st)

    server_ip = m._get_server_ip()
    domain = m._detect_server_domain() or ""
    port_str = (str(st["exit"]["port_start"])
                if st["exit"]["port_start"] == st["exit"]["port_end"]
                else f"{st['exit']['port_start']}-{st['exit']['port_end']}")
    m._box_top("✅  EXIT НАСТРОЕН — данные для Entry")
    m._box_row()
    m._box_kv("Host:", f"{m.YELLOW}{domain or server_ip}{m.NC}"
              + (f" {m.DIM}(IP: {server_ip}){m.NC}" if domain else ""))
    m._box_kv("Порт(ы):", f"{m.YELLOW}{port_str}/{st['exit']['protocol']}{m.NC}")
    m._box_kv("Hop-логин:", f"{m.YELLOW}{username}{m.NC}")
    m._box_kv("Hop-пароль:", f"{m.YELLOW}{password}{m.NC}")
    m._box_kv("Обфускация:", f"{m.YELLOW}{tp_name}{m.NC} "
              f"{m.DIM}(выбрать ту же на Entry для хопа){m.NC}")
    m._box_row()
    m._box_info("Перенесите эти данные на Entry (RU): меню Mieru → [C] →")
    m._box_info("[3] Управление Exit-нодами → Добавить.")
    m._box_bot()
    m._pause()

    # прямые ссылки этого сервера (одиночный режим — без каскада)
    _show_client_links(st)


# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ EXIT-НОДАМИ (Entry)
# ══════════════════════════════════════════════════════════════════════════════

def _prompt_exit() -> Optional[dict]:
    m = _mieru()
    label = proto_ask(f"  {m.CYAN}Метка (латиница, <=24): {m.NC}", c=True).strip()
    if not _RE_LABEL.match(label):
        print(f"  {m.RED}✗{m.NC} недопустимая метка"); return None
    host = proto_ask(f"  {m.CYAN}Host Exit (IP/домен): {m.NC}", c=True).strip()
    if not _RE_HOST.match(host):
        print(f"  {m.RED}✗{m.NC} недопустимый host"); return None
    raw_port = proto_ask(f"  {m.CYAN}Порт mita на Exit [2012]: {m.NC}",
                         default="2012", c=True).strip()
    port = int(raw_port) if raw_port.isdigit() else 2012
    raw_proto = proto_ask(
        f"  {m.CYAN}Транспорт хопа [TCP] (TCP/UDP; через RU-границу обычно TCP): {m.NC}",
        default="TCP", c=True).strip().upper()
    protocol = raw_proto if raw_proto in ("TCP", "UDP") else "TCP"
    username = proto_ask(f"  {m.CYAN}Hop-логин (с Exit): {m.NC}", c=True).strip()
    if not username:
        print(f"  {m.RED}✗{m.NC} обязателен"); return None
    raw_pass = proto_ask(f"  {m.CYAN}Hop-пароль (с Exit): {m.NC}", c=True).strip()
    if not raw_pass:
        print(f"  {m.RED}✗{m.NC} обязателен"); return None

    # обфускация хопа — паритет с аддоном (basic/aggressive/…/custom);
    # рекомендация: тот же пресет, что у mita на Exit (симметрия ног)
    print(f"  {m.DIM}(рекомендуется тот же пресет, что у mita на Exit —"
          f" см. EXIT НАСТРОЕН на Exit-ноде){m.NC}")
    hop_preset, hop_custom = _ask_pattern_menu(m, current="basic",
                                               subject="хопа")
    if hop_preset == "custom" and hop_custom is None:
        hop_preset, hop_custom = "basic", None

    socks_login = proto_ask(
        f"  {m.CYAN}SOCKS5-логин локального mieru (Enter=без): {m.NC}",
        default="", c=True).strip()
    socks_password = ""
    if socks_login:
        socks_password = proto_ask(
            f"  {m.CYAN}SOCKS5-пароль (Enter=без): {m.NC}",
            default="", c=True).strip()
    return {
        "id": f"exit-{int(time.time() * 1000) % 100000}-{label.lower()[:12]}",
        "label": label, "host": host, "port": port, "protocol": protocol,
        "username": username, "password": raw_pass,
        "hop_preset": hop_preset,
        "hop_pattern": hop_custom,
        "socks_login": socks_login, "socks_password": socks_password,
        "enabled": True, "healthy": None, "latency_ms": None,
        "last_check": "", "fail_streak": 0,
        "socks_port": 0, "redsocks_port": 0, "rpc_port": 0, "http_port": 0,
    }


def _manage_exits(st: dict) -> None:
    m = _mieru()
    while True:
        os.system("clear")
        m._box_top("🧩  EXIT-НОДЫ  •  управление (Entry)")
        m._box_row()
        exits = st.get("exits", [])
        if not exits:
            m._box_row(f"  {m.DIM}Exit-нод нет. Добавьте данные с Exit-сервера.{m.NC}")
        for i, e in enumerate(exits, 1):
            state_ch = (f"{m.GREEN}●" if e.get("healthy") is True else
                        f"{m.RED}●" if e.get("healthy") is False else "○")
            en = "" if e.get("enabled", True) else f" {m.DIM}(выкл){m.NC}"
            lat = f" {m.DIM}{e.get('latency_ms')}мс{m.NC}" if e.get("latency_ms") else ""
            hop_tp = e.get("hop_preset") or e.get("hop_pattern") and "custom" \
                or "(наслед.)"
            m._box_row(f"  {state_ch}{m.NC} {i}. {m.YELLOW}{e['label']}{m.NC} "
                       f"→ {e['host']}:{e['port']}/{e['protocol']}"
                       f"{en}{lat}")
            m._box_row(f"     {m.DIM}обфускация хопа: {hop_tp}{m.NC}")
        m._box_row()
        m._box_item("1", "Добавить Exit")
        m._box_item("2", "Удалить Exit")
        m._box_item("3", "Вкл/выкл Exit")
        m._box_item("4", "Поднять в списке (приоритет для prio)")
        m._box_item("5", "🔒 Обфускация хопа (сменить пресет Exit)")
        m._box_item("S", "Strict-UDP: " + ("вкл" if st.get("strict_udp_block") else "выкл"))
        m._box_item("Q", "← Назад")
        m._box_bot(); print()
        try:
            ch = proto_ask(f"{m.CYAN}Выбор: {m.NC}", c=True).strip().lower()
        except ProtoCancelled:
            return

        if ch == "1":
            e = _prompt_exit()
            if e:
                if any(x["host"] == e["host"] and x["port"] == e["port"]
                       for x in st.get("exits", [])):
                    print(f"  {m.YELLOW}⚠{m.NC} такой host:port уже есть — всё равно добавляю")
                st.setdefault("exits", []).append(e)
                state_save(st)
        elif ch == "2" and exits:
            raw = proto_ask("  № для удаления: ", c=True).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(exits):
                victim = exits.pop(int(raw) - 1)
                # гигиена состава: id удалённого не должен оставаться
                # в lb_exits (иначе нормализатор молча отфильтрует,
                # а state — мусорить)
                if victim["id"] in (st.get("lb_exits") or []):
                    st["lb_exits"] = [x for x in st["lb_exits"]
                                       if x != victim["id"]]
                _release_ports_of_exit(victim)
                _run(["systemctl", "disable", "--now",
                      f"mieru-hop@{victim['id']}"], capture=True)
                _run(["systemctl", "disable", "--now",
                      f"mieru-cascade-redsocks@{victim['id']}"], capture=True)
                (_ETC_DIR / f"redsocks-{victim['id']}.conf").unlink(missing_ok=True)
                state_save(st)
        elif ch == "3" and exits:
            raw = proto_ask("  № для переключения: ", c=True).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(exits):
                e = exits[int(raw) - 1]
                e["enabled"] = not e.get("enabled", True)
                state_save(st)
        elif ch == "4" and len(exits) > 1:
            raw = proto_ask("  № поднять: ", c=True).strip()
            if raw.isdigit() and 2 <= int(raw) <= len(exits):
                i = int(raw) - 1
                exits.insert(i - 1, exits.pop(i))
                state_save(st)
        elif ch == "5" and exits:
            raw = proto_ask("  № Exit (обфускация хопа): ", c=True).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(exits):
                e = exits[int(raw) - 1]
                cur = e.get("hop_preset") or "basic"
                name, custom = _ask_pattern_menu(m, current=cur, subject="хопа")
                if name == "custom" and custom is None:
                    name, custom = "basic", None
                e["hop_preset"] = name
                e["hop_pattern"] = custom
                state_save(st)
                print(f"  {m.GREEN}✓{m.NC} обфускация хопа {e['label']}: "
                      f"{name} — применится при [4] Применить")
        elif ch == "s":
            st["strict_udp_block"] = not st.get("strict_udp_block", False)
            state_save(st)
        elif ch in ("q", ""):
            return


# ══════════════════════════════════════════════════════════════════════════════
#  КЛИЕНТСКАЯ ВЫДАЧА (ссылки) — порт из mieru addon (hybrid_addon)
#  + standalone-флоу mieru.py: Karing mierus:// (+traffic-pattern blob),
#  Nekobox/Nyamebox mierus://, sing-box JSON для Karing (запасной), QR
# ══════════════════════════════════════════════════════════════════════════════

def _export_traffic_pattern_blob() -> Optional[str]:
    """`mita export traffic-pattern` → base64-protobuf blob для mierus://
    и sing-box JSON (порт hybrid_addon._export_traffic_pattern_blob).

    Blob ЛОКАЛЬНОГО mita = паттерн того сервера, к которому клиент
    подключается: Entry — каскадная выдача, Exit — одиночная. None при
    любой проблеме — выдача продолжится без поля (не критично)."""
    m = _mieru()
    try:
        if not m._MITA_BIN.exists():
            return None
    except Exception:
        return None
    r = _run([str(m._MITA_BIN), "export", "traffic-pattern"], capture=True)
    if r.returncode != 0:
        print("  [!] mita export traffic-pattern не удался — "
              "ссылки будут без traffic-pattern")
        return None
    return (r.stdout or "").strip() or None


def _show_client_links(st: dict, pick_user: bool = False) -> None:
    """Клиентская выдача каскада (порт hybrid_addon._show_mieru_client_links
    + форматы standalone mieru.py — переиспользует его генераторы лениво).

    Роль entry: ссылки для КОНЕЧНЫХ клиентов — подключаются к mita
    ЭТОГО сервера (Entry), egress через Exit-ноды. Роль exit: прямые
    ссылки этого сервера (одиночный режим), hop-юзер исключается.

    Особенности форматов (наследованы из mieru.py, проверены живьём):
      • Karing UDP — с IP (баг ядра Karing: домен+UDP = 0 байт/с);
        Nekobox/Nyamebox — адрес как есть
      • traffic-pattern blob: в Karing-ссылке — ДЕФИС (живьём
        подтверждён), в NekoBox-ссылке — ПОДЧЁРКИВАНИЕ traffic_pattern
        (парсер MieruBean.cpp:24; дефис приложение молча теряло);
        NekoBox-ссылку строит генератор целиком (server_ports обязателен)
      • sing-box JSON: поле traffic_pattern + dns-секция из state
        standalone-установки (client_dns), BOTH → selector-группа
    """
    m = _mieru()
    role = st.get("role") or ""
    if role not in ("entry", "exit"):
        print("  Роль не настроена — сначала [1] или [2].")
        m._pause()
        return

    mst = proto_load_state(m._MODULE_STATE)
    users = list(mst.get("users", []))
    if role == "exit":
        # hop-юзер — служебная нога Entry→Exit, в прямую выдачу не идёт
        hop = (st.get("exit", {}) or {}).get("hop_username")
        users = [u for u in users if u.get("username") != hop]
    if not users:
        print("  Пользователей нет (меню Mieru → [2]).")
        m._pause()
        return

    idx = 0
    if pick_user and len(users) > 1:
        for i, u in enumerate(users, 1):
            print(f"  {i}. {u.get('username')}")
        try:
            raw = proto_ask(f"  {m.CYAN}Пользователь [Enter=1] (q=отмена): {m.NC}",
                            default="1", c=True).strip().lower()
        except ProtoCancelled:
            return
        if raw in ("q", ""):
            return
        if raw.isdigit() and 1 <= int(raw) <= len(users):
            idx = int(raw) - 1
    u = users[idx]
    uname = u.get("username", "")
    pwd = u.get("password", "")

    try:
        import urllib.parse
        from chimera.modules.mieru import (
            _gen_client_share_link,
            _gen_client_share_link_nekobox,
            _gen_singbox_outbound,
            _build_karing_full_config,
            _build_karing_multi_config,
            _karing_link_addr,
            _dns_host_is_domain,
            _effective_client_addr,
            _protocol_variants,
            _print_qr,
            _print_link_pairs_outside,
        )
    except ImportError as e:
        print(f"  [!] генераторы ссылок недоступны: {e}")
        m._pause()
        return

    port_start = int(mst.get("port_start", m._DEFAULT_PORT_START))
    port_end = int(mst.get("port_end", m._DEFAULT_PORT_END))
    protocol = mst.get("protocol", m._DEFAULT_PROTOCOL)
    client_dns = (mst.get("client_dns", "") or "").strip()
    client_addr = _effective_client_addr()
    blob = _export_traffic_pattern_blob()

    variants = _protocol_variants(protocol)
    server_domain = client_addr if _dns_host_is_domain(client_addr) else ""
    link_pairs = []
    outbounds = []
    udp_ip_used = False
    for p in variants:
        # Karing-выдача UDP — с IP (баг ядра Karing, см. mieru.py)
        k_addr, sub = _karing_link_addr(p, client_addr)
        udp_ip_used = udp_ip_used or sub
        karing = _gen_client_share_link(
            k_addr, port_start, port_end, p, uname, pwd,
            traffic_preset="" if blob else "basic")
        # NekoBox/Nyamebox: формат строит генератор (server_ports +
        # multiplexing + traffic_pattern ПОДЧЁРКИВАНИЕМ — парсер
        # MieruBean.cpp читает именно так; дефис он молча терял)
        neko = _gen_client_share_link_nekobox(
            client_addr, port_start, p, uname, pwd,
            traffic_pattern=blob or "", port_end=port_end)
        if blob:
            # Karing: паттерн ДЕФИСОМ — живьём подтверждён импортом
            # (гибрид/каскад всегда несут ровно один traffic-pattern)
            tp = "traffic-pattern=" + urllib.parse.quote(blob, safe="")
            karing = f"{karing}&{tp}"
        link_pairs.append((p, karing, neko))
        ob = _gen_singbox_outbound(k_addr, port_start, port_end, p,
                                   uname, pwd)
        if blob:
            # поле sing-box (snake_case) несёт тот же blob, что и ссылка
            ob["traffic_pattern"] = blob
        if len(variants) > 1:
            ob["tag"] = f"{ob['tag']}-{p.lower()}"
        outbounds.append(ob)

    # BOTH — ОБА транспорта в одном JSON + selector; один — обычный конфиг
    if len(outbounds) > 1:
        full_config = _build_karing_multi_config(outbounds, client_dns,
                                                 server_domain)
    else:
        full_config = _build_karing_full_config(outbounds[0], client_dns,
                                                server_domain)
    mode = "cascade" if role == "entry" else "exit"
    cfg_path = Path(f"/tmp/karing-mieru-{mode}-{uname}.json")
    cfg_saved = False
    try:
        cfg_path.write_text(
            json.dumps(full_config, indent=2, ensure_ascii=False),
            encoding="utf-8")
        cfg_saved = True
    except OSError:
        pass

    os.system("clear")
    if role == "entry":
        m._box_top("🔗  КЛИЕНТСКАЯ ВЫДАЧА  •  КАСКАД")
        m._box_row()
        for e in st.get("exits", []):
            if not e.get("enabled", True):
                continue
            mark = (f"{m.GREEN}●{m.NC}" if e.get("healthy") is True else
                    f"{m.RED}●{m.NC}" if e.get("healthy") is False else "○")
            m._box_row(f"  {mark} {e['label']} → {e['host']} "
                       f"{m.DIM}(egress){m.NC}")
        m._box_row()
        m._box_info("Клиенты подключаются к ЭТОМУ серверу (Entry, RU);")
        m._box_info("исходящий IP = Exit-нода(ы) выше.")
    else:
        m._box_top("🔗  КЛИЕНТСКАЯ ВЫДАЧА  •  ОДИНОЧНЫЙ РЕЖИМ")
        m._box_row()
        m._box_info("Прямое подключение к этому серверу (Exit, EU),")
        m._box_info("без каскада. Каскадная выдача — на Entry-ноде.")
    m._box_row()
    port_str = str(port_start) if port_start == port_end \
        else f"{port_start}-{port_end}"
    m._box_kv("Пользователь:", f"{m.YELLOW}{uname}{m.NC}")
    m._box_kv("Пароль:", f"{m.YELLOW}{pwd}{m.NC}")
    m._box_kv("Сервер:", f"{m.YELLOW}{client_addr}{m.NC}")
    m._box_kv("Порт(ы):", f"{m.YELLOW}{port_str}/"
              f"{'+'.join(variants)}{m.NC}")
    if client_dns:
        m._box_kv("DNS (через туннель):", f"{m.YELLOW}{client_dns}{m.NC}")
    tp_label = mst.get("traffic_preset", "basic")
    m._box_kv("Обфускация:", f"{m.YELLOW}{tp_label}{m.NC}")
    m._box_row()
    m._box_info("Ссылки Karing и Nekobox/Nyamebox — ПОД рамкой, целиком.")
    if cfg_saved:
        m._box_info(f"Karing JSON (запасной): {cfg_path}")
    if blob:
        m._box_info("traffic-pattern — blob от mita (обфускация клиента")
        m._box_info("синхронизирована с сервером автоматически)")
    if udp_ip_used:
        m._box_warn("UDP для Karing — с IP: домен+UDP в Karing не работает")
    m._box_warn("Karing: ядро sing-box (не Xray-core); время ±30 сек!")
    if len(users) > 1:
        m._box_info(f"Другие пользователи: меню каскада → [L] "
                    f"(всего {len(users)})")
    m._box_bot()
    print()
    _print_link_pairs_outside(link_pairs)
    for p, share_link, _neko in link_pairs:
        _print_qr(share_link,
                  f"Karing / mierus:// для {uname} ({p})"
                  if len(link_pairs) > 1 else
                  f"Karing / mierus:// для {uname}")
    m._pause()


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH + РЕБАЛАНС
# ══════════════════════════════════════════════════════════════════════════════

def _probe_exit_tcp(e: dict) -> Optional[int]:
    try:
        t0 = time.time()
        with socket.create_connection(
                (e["host"], int(e["port"])), timeout=_TCP_PROBE_TIMEOUT):
            return int((time.time() - t0) * 1000)
    except OSError:
        return None


def _probe_exit_e2e(e: dict) -> bool:
    """E2E hop-ноги реальным клиентом (изолированный HOME инстанса)."""
    m = _mieru()
    d = _instance_dir(e)
    if not d.exists() or not m._MIERU_BIN.exists():
        return False
    env = dict(os.environ)
    env["HOME"] = str(d)
    env["XDG_CONFIG_HOME"] = str(d / ".config")
    try:
        r = subprocess.run([str(m._MIERU_BIN), "test", _E2E_URL],
                           capture_output=True, text=True, check=False,
                           timeout=_PROBE_TIMEOUT, env=env)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        return r.returncode == 0 and "Connected to" in out
    except (subprocess.TimeoutExpired, OSError):
        return False


def _ensure_local_services(st: dict) -> list:
    """Self-healing локальных ног каскада (mieru-hop — само-форк демон,
    systemd не видит смерть форк-ребёнка при oneshot+RemainAfterExit).

    Проба TCP на 127.0.0.1:socks_port каждого включённого Exit; если
    слушателя нет — restart пары юнитов (restart oneshot = stop+start).
    Возвращает список id, для которых был рестарт.
    """
    restarted = []
    for e in st.get("exits", []):
        if not e.get("enabled", True):
            continue
        sp = e.get("socks_port")
        alive = False
        if sp:
            try:
                with socket.create_connection(("127.0.0.1", int(sp)),
                                              timeout=1.0):
                    alive = True
            except OSError:
                alive = False
        if alive:
            continue
        _run(["systemctl", "restart", f"mieru-hop@{e['id']}"], capture=True)
        _run(["systemctl", "restart",
              f"mieru-cascade-redsocks@{e['id']}"], capture=True)
        restarted.append(e["id"])
    return restarted


# Гистерезис дрейфа весов: без порога микро-джиттер метрик
# каждый тик давал «новые» вероятности — и health-тик ежеминутно делал
# полную пересборку правил каскада + persist rules.v4 (живой кейс
# entry-ноды с leastping, октябрь 2026).
WEIGHTS_HYSTERESIS = 0.05   # 5 процентных пунктов по доле Exit-а
WEIGHTS_REBUILD_COOLDOWN_S = 600   # весовой ребаланс — не чаще раза в 10 мин


def _shares_materially_changed(old_bal: Optional[dict],
                               new_bal: Optional[dict]) -> bool:
    """Доли Exit-ов изменились МАТЕРИАЛЬНО? (гистерезис ребаланса)

    False — джиттер: состав Exit-ов тот же и все доли в пределах
    WEIGHTS_HYSTERESIS от последней ПРИМЕНЁННОЙ (st['balance']).
    True — смена состава Exit-ов или чья-то доля ушла больше порога:
    ребаланс обязателен. old_bal=None/пусто (не применяли / stale) →
    True — самовыправится первым apply."""
    old = (old_bal or {}).get("shares") or {}
    new = (new_bal or {}).get("shares") or {}
    if set(old) != set(new):
        return True
    return any(abs(new[i] - old.get(i, 0.0)) > WEIGHTS_HYSTERESIS
               for i in new)


def health_tick(verbose: bool = False) -> dict:
    """Проверка всех Exit-ов; при смене состояния — ребаланс правил.

    Всё тело — под _cascade_lock (сериализация с TUI-хендлерами,
    фикс гонки 01.10). Каждый тик СВЕРЯЕТ живые правила с
    st['applied_rules'] (iptables -S скан) и перестраивает при
    расхождении — самозалечивание сбоев apply, ручных правок и
    частичного flush."""
    with _cascade_lock():
        return _health_tick_locked(verbose)


def _health_tick_locked(verbose: bool = False) -> dict:
    m = _mieru()
    st = state_load()
    result = {"checked": 0, "changed": [], "rebalanced": False}
    if st.get("role") != "entry":
        return result
    # self-healing локальных ног (до проб Exit-ов — мёртвый хоп без
    # слушателя исказил бы E2E-вердикт)
    restarted_local = _ensure_local_services(st)
    if restarted_local and verbose:
        print(f"  {m.YELLOW}⟳{m.NC} рестарт локальных сервисов: "
              f"{', '.join(restarted_local)}")
        time.sleep(3)          # дать mieru start подняться до проб
    changed_before = {e["id"]: e.get("healthy") for e in st.get("exits", [])}

    for e in st.get("exits", []):
        if not e.get("enabled", True):
            continue
        result["checked"] += 1
        latency = _probe_exit_tcp(e)
        e2e_ok = _probe_exit_e2e(e) if latency is not None else False
        ok = e2e_ok or (latency is not None and e.get("healthy") is True)
        # e2e — авторитетный; TCP-only допускаем только как «скорее жив»
        # при прошлом healthy=True (кратковременный сбой цели E2E)
        if e2e_ok:
            e["healthy"], e["fail_streak"] = True, 0
        else:
            e["fail_streak"] = int(e.get("fail_streak", 0)) + 1
            if e["fail_streak"] >= 2:
                e["healthy"] = False
        e["latency_ms"] = latency
        e["last_check"] = _ts()
        if verbose:
            mark = (m.GREEN + "✓" if e["healthy"] else m.RED + "✗") + m.NC
            print(f"  {mark} {e['label']}: "
                  f"{'E2E OK' if e2e_ok else 'E2E fail'}, "
                  f"tcp={latency if latency is not None else '—'}мс")

    changed = [e["id"] for e in st.get("exits", [])
               if changed_before.get(e["id"]) is not e.get("healthy")]

    # весовые стратегии: пересчёт долей; МАТЕРИАЛЬНЫЙ дрейф = ребаланс.
    # При закреплённом Exit стратегии не действуют — проб не делаем.
    weights_drift = False
    if ((st.get("strategy") or "").lower() in METRIC_STRATEGIES
            and not st.get("pinned_exit")):
        try:
            bal = _balance_shares(st, _lb_effective_exits(st))
            result["balance"] = bal
            fresh = _rule_specs(st, bal)
            # Гистерезис + cooldown: доли в пределах
            # WEIGHTS_HYSTERESIS от последней применённой — НЕ повод
            # для пересборки; даже материальный дрейф — не чаще раза в
            # WEIGHTS_REBUILD_COOLDOWN_S (EMA-сглаженные метрики
            # осциллируют редко). Без этого тик перестраивал правила
            # (~90 вызовов iptables) и персистил rules.v4 каждую минуту.
            weights_drift = (
                (time.time() - float(st.get("weights_applied_ts") or 0)
                 >= WEIGHTS_REBUILD_COOLDOWN_S)
                and _shares_materially_changed(st.get("balance"), bal)
                and fresh != (st.get("applied_rules") or []))
        except Exception:
            weights_drift = False

    # сверка живых правил с применёнными (фикс гонки 01.10: state
    # говорил «пин fi1», ядро — «пин pl1» — и так до бесконечности).
    # None (iptables -S не ответил) — не повод перестраивать наугад.
    # Ядерные стратегии и пин: спеки детерминированы — сверяем и с
    # ними (смена состава Exit-ов без [4] не оставляет хвостов).
    out_of_sync = (_rules_in_sync(st) is False)
    if (not out_of_sync and st.get("applied_rules")
            and ((st.get("strategy") or "rr").lower() not in METRIC_STRATEGIES
                 or st.get("pinned_exit"))):
        try:
            out_of_sync = _rule_specs(st) != st["applied_rules"]
        except Exception:
            out_of_sync = False

    if changed or weights_drift or out_of_sync:
        result["changed"] = changed
        result["rebalanced"] = True
        if out_of_sync and not (changed or weights_drift):
            result["resynced"] = True
        _rules_apply(st)
        _ROUTING_SH.write_text(_routing_sh_text(st))
        if verbose:
            why = []
            if changed:
                why.append("health: " + ", ".join(changed))
            if out_of_sync:
                why.append("правила не соответствуют state "
                            "(сверка iptables -S)")
            if weights_drift:
                # bal гарантированно определён: weights_drift=True только
                # если try дошёл до сравнения fresh (после bal=...)
                sh = " · ".join(
                    f"{k} {v:.0%}" for k, v in
                    sorted((bal.get("shares") or {}).items(),
                           key=lambda kv: -kv[1]))
                tail = f": {sh}" if sh else ""
                why.append(f"веса стратегии ({st.get('strategy')}) "
                           f"изменились{tail}")
            print(f"  {m.YELLOW}⟳{m.NC} правила перестроены ({'; '.join(why)})")
            # пиннинг: переходы фаз A/B (порт dpi_detector VLESS)
            if st.get("pinned_exit"):
                pre_exits = [{**e,
                              "healthy": changed_before.get(e["id"])}
                             for e in st.get("exits", [])]
                pre_st = {**st, "exits": pre_exits}
                pin_pre = _effective_pinned(pre_st, _active_exits(pre_st))
                pin_post = _effective_pinned(st, _active_exits(st))
                if pin_pre[0] is not pin_post[0] and pin_post[0] is not None:
                    labels = {e["id"]: (e.get("label") or e["id"])
                              for e in st.get("exits", [])}
                    pin_lbl = labels.get(st["pinned_exit"],
                                         st["pinned_exit"])
                    eff_lbl = pin_post[0].get("label") or pin_post[0]["id"]
                    if pin_post[1]:      # фаза B — деградация
                        print(f"  {m.YELLOW}📌{m.NC} пиннинг: {pin_lbl} "
                              f"недоступен → трафик через {eff_lbl} "
                              f"(fallback; возврат при восстановлении)")
                    else:                # фаза A — восстановление
                        pre_lbl = (pin_pre[0].get("label")
                                   if pin_pre[0] else "—")
                        print(f"  {m.GREEN}📌{m.NC} пиннинг: {pin_lbl} "
                              f"восстановлен → возврат с {pre_lbl}")
    state_save(st)
    # b4-exempt: освежить ipset блок-листа (RU-вид + вид каждого живого
    # Exit; TTL CDN 60-300с — см. секцию B4-EXEMPT). Под локом тика:
    # ~10-25с сети, TUI-меню в это время честно ждёт (wait_hint).
    if _b4_exempt_active(st):
        _b4set_refresh(st, verbose=verbose)
    return result


def health_tick_cli() -> None:
    health_tick(verbose=False)


# ══════════════════════════════════════════════════════════════════════════════
#  ДЕАКТИВАЦИЯ / УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════

def _stop_units(st: dict) -> None:
    for e in st.get("exits", []):
        _run(["systemctl", "disable", "--now", f"mieru-hop@{e['id']}"], capture=True)
        _run(["systemctl", "disable", "--now",
              f"mieru-cascade-redsocks@{e['id']}"], capture=True)
    for u in ("mieru-cascade-routing", "mieru-cascade-health.timer"):
        _run(["systemctl", "disable", "--now", u], capture=True)


def _strip_rules(st: dict) -> None:
    """Удалить все свои правила (оба матчера — cgroup и owner)."""
    # точные применённые (веса/вероятности неперечислимы)
    for sp in st.get("applied_rules") or []:
        while True:
            r = _run(_spec_argv(sp, add=False), capture=True)
            if r.returncode != 0:
                break
    for mode in ("cgroup", "owner"):
        probe = dict(st)
        probe["matcher"] = mode
        if mode == "owner" and _mita_uid() is None:
            continue
        for sp in _rule_specs_all_variants(probe):
            while True:
                r = _run(_spec_argv(sp, add=False), capture=True)
                if r.returncode != 0:
                    break
    _purge_orphan_rules(st)
    st["applied_rules"] = []
    st["balance"] = None
    proto_ipt_persist()


def deactivate(st: dict, keep_state: bool = True) -> None:
    """Снять правила, остановить сервисы. Exit-сторона: удалить hop-пользователя."""
    m = _mieru()
    role = st.get("role")
    if role == "entry":
        _stop_units(st)
        # под локом: снять правила и роль одним куском — тик между
        # ними успел бы перестроить правила (state ещё считал роль
        # entry, applied уже пуст)
        with _cascade_lock():
            _strip_rules(st)
            _b4set_destroy()
            _ROUTING_SH.unlink(missing_ok=True)
            if keep_state:
                st["role"] = ""
                state_save(st)
        if not keep_state:
            _MODULE_STATE.unlink(missing_ok=True)
        return
    elif role == "exit":
        ex = st.get("exit", {})
        uname = ex.get("hop_username")
        if uname:
            mst = proto_load_state(m._MODULE_STATE)
            users = [u for u in mst.get("users", [])
                     if u.get("username") != uname]
            mst["users"] = users
            cfg = m._build_server_config(
                users,
                mst.get("port_start", m._DEFAULT_PORT_START),
                mst.get("port_end", m._DEFAULT_PORT_END),
                mst.get("protocol", m._DEFAULT_PROTOCOL),
                traffic_pattern=m._MIERU_TRAFFIC_PRESETS.get(
                    mst.get("traffic_preset", "basic"), {}).get("config"))
            if m._apply_server_config(cfg) is None:
                proto_save_state(m._MODULE_STATE, mst)
                _run(["systemctl", "reload-or-restart", m._SERVICE_NAME])
    if keep_state:
        st["role"] = ""
        state_save(st)
    else:
        _MODULE_STATE.unlink(missing_ok=True)


def _full_uninstall(st: dict) -> None:
    m = _mieru()
    deactivate(st, keep_state=False)
    # порты: реестр + ufw (чужие правила не трогаем)
    for entry in port_list_for_service(SERVICE_MIERU_CASCADE):
        ufw_close_port(int(entry.get("port", 0)), "tcp", SERVICE_MIERU_CASCADE)
    port_unregister(SERVICE_MIERU_CASCADE)
    # файлы и юниты
    for e in st.get("exits", []):
        (_ETC_DIR / f"redsocks-{e['id']}.conf").unlink(missing_ok=True)
    for u in (_UNIT_HOP, _UNIT_REDSOCKS, _UNIT_ROUTING,
              _UNIT_HEALTH, _UNIT_HEALTH_T):
        u.unlink(missing_ok=True)
    _HEALTH_WRAPPER.unlink(missing_ok=True)
    shutil.rmtree(_ETC_DIR, ignore_errors=True)
    shutil.rmtree(_INST_DIR, ignore_errors=True)
    if st.get("matcher") == "owner":
        _remove_owner_dropin()
    _run(["systemctl", "daemon-reload"])
    print(f"  {m.GREEN}✓{m.NC} mieru-cascade удалён")


# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════

def _show_status(st: dict) -> None:
    m = _mieru()
    m._box_top("📊  СТАТУС КАСКАДА")
    m._box_row()
    role = st.get("role") or "—"
    m._box_kv("Роль:", f"{m.CYAN}{role}{m.NC}")
    if st.get("role") == "entry":
        m._box_kv("Матчинг:", str(st.get("matcher")))
        m._box_kv("Стратегия:", str(st.get("strategy")))
        m._box_kv("Состав LB:", _lb_exits_summary(st))
        if st.get("pinned_exit"):
            labels = {e["id"]: (e.get("label") or e["id"])
                      for e in st.get("exits", [])}
            pin_lbl = labels.get(st["pinned_exit"], st["pinned_exit"])
            pin_eff, fb_from = _effective_pinned(st, _active_exits(st))
            if pin_eff is not None and not fb_from:
                m._box_kv("Закреплён Exit:",
                          f"{m.CYAN}{pin_eff.get('label')}{m.NC} "
                          f"{m.DIM}(стратегия не действует){m.NC}")
            elif pin_eff is not None:
                m._box_kv("Закреплён Exit:",
                          f"{pin_lbl} {m.RED}⚠ недоступен{m.NC}")
                m._box_kv("Fallback:",
                          f"{m.YELLOW}{pin_eff.get('label')}{m.NC} "
                          f"{m.DIM}(возврат при восстановлении){m.NC}")
            else:
                m._box_kv("Закреплён Exit:",
                          f"{pin_lbl} {m.RED}⚠ живых Exit-ов нет{m.NC}")
        bal = st.get("balance") or {}
        if bal.get("shares") and not st.get("pinned_exit"):
            shares = "  ".join(
                f"{k}:{v:.0%}" for k, v in
                sorted(bal["shares"].items(), key=lambda kv: -kv[1]))
            m._box_kv("Доли (посл. расчёт):", shares)
        m._box_kv("Strict UDP:", "вкл" if st.get("strict_udp_block") else "выкл")
        m._box_sep()
        for e in st.get("exits", []):
            h = e.get("healthy")
            hs = (f"{m.GREEN}жив" if h is True else
                  f"{m.RED}недоступен" if h is False else f"{m.DIM}не проверялся")
            svc = _run(["systemctl", "is-active", f"mieru-hop@{e['id']}"],
                       capture=True).stdout.strip()
            rs = _run(["systemctl", "is-active",
                       f"mieru-cascade-redsocks@{e['id']}"],
                      capture=True).stdout.strip()
            m._box_row(f"  {m.YELLOW}{e['label']}{m.NC} → {e['host']}:{e['port']}")
            m._box_row(f"     hop={svc or '—'} redsocks={rs or '—'} "
                       f"| {hs} | {e.get('latency_ms') or '—'}мс "
                       f"| socks:{e.get('socks_port') or '—'} "
                       f"redir:{e.get('redsocks_port') or '—'}")
            hop_tp = e.get("hop_preset") or (
                "custom" if e.get("hop_pattern") else "(наслед. Entry)")
            m._box_row(f"     обфускация хопа: {hop_tp} "
                       f"{m.DIM}(рекомендуется = пресету mita на Exit){m.NC}")
            if e.get("last_check"):
                m._box_row(f"     {m.DIM}проверка: {e['last_check']}{m.NC}")
        # весовые стратегии: вероятности неперечислимы без снапшота долей —
        # честный счётчик по применённому набору (st['applied_rules'],
        # точный replay); иначе статус показывал бы «1/1» вместо «5/5»
        cnt_specs = (
            st["applied_rules"]
            if (st.get("strategy") or "").lower() in METRIC_STRATEGIES
            and st.get("applied_rules") else _rule_specs(st))
        rules_now = sum(
            1 for sp in cnt_specs
            if proto_ipt_rule_exists(sp["table"], sp["chain"], sp["rest"]))
        m._box_sep()
        m._box_kv("Правил в системе:", f"{rules_now}/{len(cnt_specs)}")
        if _rules_in_sync(st) is False:
            m._box_kv("Сверка с ядром:",
                      f"{m.RED}рассинхрон — тик исправит ≤2 мин{m.NC}")
        r = _run(["systemctl", "is-active", "mieru-cascade-health.timer"],
                 capture=True)
        m._box_kv("Health-timer:", r.stdout.strip() or "—")
        m._box_row()
        m._box_info("UDP-нагрузка mita идёт напрямую с Entry (RU-IP);"
                    if not st.get("strict_udp_block") else
                    "Strict-UDP: нагрузка mita блокируется (кроме loopback)")
    elif st.get("role") == "exit":
        ex = st.get("exit", {})
        m._box_kv("Hop-логин:", str(ex.get("hop_username", "—")))
        m._box_kv("Порт(ы):", f"{ex.get('port_start', '—')}-{ex.get('port_end', '—')}"
                  f"/{ex.get('protocol', '—')}")
        if ex.get("traffic_preset"):
            m._box_kv("Обфускация mita:", str(ex.get("traffic_preset")))
        mst = proto_load_state(m._MODULE_STATE)
        if mst.get("traffic_preset"):
            m._box_kv("Пресет (state):", str(mst.get("traffic_preset")))
    m._box_bot()
    m._pause()


# ══════════════════════════════════════════════════════════════════════════════
#  BACKUP REGISTRY (конвенция: get_backup_paths на уровне модуля)
# ══════════════════════════════════════════════════════════════════════════════

def get_backup_paths() -> list:
    """Состояние каскада + redsocks-конфиги (юниты регенерируются)."""
    out = []
    try:
        if _MODULE_STATE.exists():
            out.append((_MODULE_STATE, "mieru_cascade/mieru_cascade.json"))
        if _ETC_DIR.is_dir():
            for f in sorted(_ETC_DIR.glob("redsocks-*.conf")):
                out.append((f, f"mieru_cascade/{f.name}"))
    except Exception:
        return []
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════

def set_lb_exits(exits: Optional[list]) -> bool:
    """Сменить состав Exit-ов для балансировки (меню [E] / API).

    Порт awg_cascade_lb.lb_set_exits (06.10): exits — ids ИЛИ метки
    Exit-ов (пара/подмножество/сколько угодно — из всего флота);
    None/пусто = все. На лету (role=entry, Exit-ы есть): пересборка
    правил + routing.sh; EMA-история и доли ушедших чистятся (форс-
    ребаланс). Явный выбор с <2 известных включённых — отклонено
    (False), прежний состав сохраняется. Пиннинг не трогаем: закреплённый
    Exit вне состава продолжает работать (override юзера)."""
    m = _mieru()
    with _cascade_lock(wait_hint=True):
        fresh = state_load()              # ребаза (фикс гонки 01.10)
        if fresh.get("role") != "entry":
            print("  Состав балансировки имеет смысл только для Entry ([1]).")
            return False
        all_exits = fresh.get("exits", [])
        sel = _normalize_lb_selection(exits, all_exits)
        enabled_ids = {e["id"] for e in all_exits
                       if e.get("enabled", True)}
        if exits and sum(1 for x in sel if x in enabled_ids) < 2:
            print("  В выборе <2 известных включённых Exit-ов — отклонено.")
            return False
        fresh["lb_exits"] = sel
        # EMA ушедших — в мусор; доли — сброс (форс-ребаланс тиком)
        eff = _lb_effective_exits(fresh)
        eff_labels = {e.get("label") or e["id"] for e in eff}
        ema = fresh.get("metrics_ema")
        if isinstance(ema, dict):
            for k in list(ema):
                if k not in eff_labels:
                    ema.pop(k, None)
        fresh["balance"] = None
        if all_exits:
            ok = _rules_apply(fresh)
            _ROUTING_SH.write_text(_routing_sh_text(fresh))
        else:
            state_save(fresh)
            ok = True
    labels = {e["id"]: (e.get("label") or e["id"]) for e in all_exits}
    names = ", ".join(labels[i] for i in sel) if sel else "все"
    print(f"  {m.GREEN}✓{m.NC} состав балансировки: {names}")
    try:      # TG-уведомление — best effort (монитор шлёт сам)
        from chimera.modules.mieru_cascade_monitor import _tg_send
        _tg_send(f"Mieru-каскад: состав балансировки Exit-ов — {names}",
                 "cascade_lb_change")
    except Exception:
        pass
    return ok


def _change_lb_exits(st: dict) -> None:
    """[E] Состав балансировки Exit-ов (пара/подмножество из флота)."""
    m = _mieru()
    if st.get("role") != "entry":
        print("  Состав балансировки имеет смысл только для Entry ([1]).")
        m._pause()
        return
    enabled = [e for e in st.get("exits", []) if e.get("enabled", True)]
    if len(enabled) < 2:
        print("  Меньше двух включённых Exit-ов — состав выбирать нечего.")
        m._pause()
        return
    cur = set(_normalize_lb_selection(st.get("lb_exits"),
                                      st.get("exits", [])))
    m._box_top("🧮  Состав балансировки Exit-ов")
    m._box_row()
    m._box_info("Балансировка ТОЛЬКО между выбранными Exit-ами (пара,")
    m._box_info("тройка, сколько угодно — из всего списка). Enter = все.")
    if st.get("pinned_exit"):
        m._box_row()
        m._box_warn("закреплён Exit — состав не действует до снятия [P]")
    m._box_row()
    for i, e in enumerate(enabled, 1):
        mark = (f" {m.GREEN}◀ в составе{m.NC}"
                if e["id"] in cur else "")
        m._box_item(str(i),
                    f"{e.get('label')} → {e.get('host')}:{e.get('port')}{mark}")
    m._box_row()
    m._box_bot(); print()
    raw = proto_ask(f"  {m.CYAN}Номера через запятую [Enter=все]: {m.NC}",
                    default="", c=True).strip()
    if not raw:
        if not st.get("lb_exits"):
            print("  Состав и так: все Exit-ы.")
            m._pause()
            return
        set_lb_exits(None)
        m._pause()
        return
    nums = [int(t) for t in re.split(r"[,\s]+", raw) if t.isdigit()]
    if not nums:
        print("  Ничего не выбрано — состав не изменён.")
        m._pause()
        return
    want = [enabled[i - 1]["id"] for i in nums
            if 1 <= i <= len(enabled)]
    set_lb_exits(want)
    m._pause()


def _change_strategy(st: dict) -> None:
    """Переключение стратегии балансировки (меню каскада → [S]).
    Меняет только правила: конфиги инстансов и сервисы от стратегии
    не зависят — полный [4] Применить не нужен."""
    m = _mieru()
    if st.get("role") != "entry":
        print("  Стратегия имеет смысл только для Entry ([1]).")
        m._pause()
        return
    current = (st.get("strategy") or "rr").lower()
    m._box_top("⚖  Стратегия балансировки Exit-ов")
    m._box_row()
    if st.get("pinned_exit"):
        m._box_warn("закреплён Exit — стратегии не действуют; снять: [P]")
        m._box_row()
    _box_strategy_items(m, current)
    bal = st.get("balance") or {}
    if bal.get("shares"):
        shares = "  ".join(
            f"{k} {v:.0%}" for k, v in
            sorted(bal["shares"].items(), key=lambda kv: -kv[1]))
        m._box_info(f"доли последнего расчёта: {m.CYAN}{shares}{m.NC}")
    m._box_info(f"состав балансировки: {m.CYAN}{_lb_exits_summary(st)}{m.NC}"
                f" {m.DIM}— смена: [E]{m.NC}")
    m._box_row()
    m._box_bot(); print()
    raw = proto_ask(f"  {m.CYAN}Выбор [Enter=текущая]: {m.NC}",
                    default="", c=True).strip().lower()
    if not raw:
        return
    by_num = {str(i): k for i, k in enumerate(BALANCE_STRATEGIES, 1)}
    pick = by_num.get(raw, raw)
    if pick not in BALANCE_STRATEGIES:
        print("  Неизвестная стратегия.")
        m._pause()
        return
    if pick == current:
        print("  Стратегия не изменилась.")
        m._pause()
        return
    # ребаза под локом: за время промпта health-тик мог сохранить
    # свои health-поля — перезагружаем state и не откатываем их (фикс
    # гонки 01.10: TUI и тик применяли правила одновременно)
    with _cascade_lock(wait_hint=True):
        fresh = state_load()
        fresh["strategy"] = pick
        ok = True
        if fresh.get("exits"):
            ok = _rules_apply(fresh)
            _ROUTING_SH.write_text(_routing_sh_text(fresh))
        else:
            state_save(fresh)
        st.update(fresh)
    if st.get("exits"):
        print(f"  {m.GREEN}✓{m.NC} стратегия: {current} → {pick}; правила "
              f"{'перестроены' if ok else 'перестроены с ошибками'}")
    else:
        print(f"  {m.GREEN}✓{m.NC} стратегия: {current} → {pick} "
              f"(правила построятся после добавления Exit-ов)")
    m._pause()


def _change_pin(st: dict) -> None:
    """Закрепление Exit-ноды ([P]) — порт pinned-режима из VLESS
    (chain_nodes «Закрепить exit-ноду»): весь трафик каскада идёт
    только через выбранный Exit, балансировка выключена. При падении
    закреплённого — fallback на живой с автоматическим возвратом
    (health-тик, фазы A/B). Меняет только правила — конфиги, сервисы
    и ссылки клиентов не зависят от пиннинга."""
    m = _mieru()
    if st.get("role") != "entry":
        print("  Закрепление имеет смысл только для Entry ([1]).")
        m._pause()
        return
    exits = [e for e in st.get("exits", []) if e.get("enabled", True)]
    if not exits:
        print("  Нет включённых Exit-ов — добавьте через [3].")
        m._pause()
        return
    current = st.get("pinned_exit")
    eff, fb_from = _effective_pinned(st, _active_exits(st))
    m._box_top("📌  Закрепить Exit-ноду  (0 = отключить)")
    m._box_row()
    m._box_info("Весь трафик каскада идёт только через выбранный Exit;")
    m._box_info("балансировка выключена. При падении — fallback на")
    m._box_info("живой Exit с автоматическим возвратом.")
    m._box_row()
    for i, e in enumerate(exits, 1):
        mark = ""
        if e["id"] == current:
            mark = f" {m.GREEN}◀ закреплён{m.NC}"
            if fb_from:
                mark += f" {m.RED}⚠ недоступен{m.NC}"
        elif eff is not None and e["id"] == eff["id"] and fb_from:
            mark = f" {m.YELLOW}◀ действует (fallback){m.NC}"
        elif e.get("healthy") is False:
            mark = f" {m.DIM}(мёртв){m.NC}"
        host = f"{e.get('host')}:{e.get('port')}"
        m._box_item(str(i), f"{e.get('label')} → {host}{mark}")
    m._box_item("0", "Отключить закрепление (вернуть балансировку)")
    m._box_row()
    m._box_bot(); print()
    raw = proto_ask(f"  {m.CYAN}Выбор [Enter=выход]: {m.NC}",
                    default="", c=True).strip().lower()
    if not raw:
        return
    if raw == "0":
        if not current:
            print("  Закрепление и так не задано.")
            m._pause()
            return
        lbl = next((e.get("label") for e in exits if e["id"] == current),
                   current)
        with _cascade_lock(wait_hint=True):
            fresh = state_load()          # ребаза (фикс гонки 01.10)
            fresh.pop("pinned_exit", None)
            if fresh.get("exits"):
                _rules_apply(fresh)
                _ROUTING_SH.write_text(_routing_sh_text(fresh))
            else:
                state_save(fresh)
            st.update(fresh)
        print(f"  {m.GREEN}✓{m.NC} закрепление снято ({lbl}) — активна "
              f"стратегия {st.get('strategy') or 'rr'}")
        m._pause()
        return
    if not raw.isdigit() or not (1 <= int(raw) <= len(exits)):
        print("  Неверный выбор.")
        m._pause()
        return
    pick = exits[int(raw) - 1]
    if pick["id"] == current:
        print("  Этот Exit уже закреплён.")
        m._pause()
        return
    with _cascade_lock(wait_hint=True):
        fresh = state_load()              # ребаза (фикс гонки 01.10)
        fresh["pinned_exit"] = pick["id"]
        if pick.get("redsocks_port"):
            _rules_apply(fresh)
            _ROUTING_SH.write_text(_routing_sh_text(fresh))
            applied_now = True
        else:
            state_save(fresh)
            applied_now = False
        st.update(fresh)
    if applied_now:
        print(f"  {m.GREEN}✓{m.NC} закреплён {pick.get('label')}: весь "
              f"трафик → {pick.get('label')}; стратегия "
              f"({st.get('strategy') or 'rr'}) не действует")
    else:
        print(f"  {m.GREEN}✓{m.NC} закреплён {pick.get('label')} "
              f"(правила построятся после [4] Применить)")
    m._pause()


def do_mieru_cascade_menu() -> None:
    """Точка входа из mieru.py (меню standalone-Mieru → [C])."""
    m = _mieru()
    while True:
        os.system("clear")
        st = state_load()
        role = st.get("role") or ""
        n_exits = len(st.get("exits", []))

        m._box_top("🧅  КАСКАД MIERU  •  Entry → Exit")
        m._box_row()
        m._box_info(f"{m.DIM}Клиент ─mTLS─► mita Entry (RU) ─redsocks─► mieru-hop{m.NC}")
        m._box_info(f"{m.DIM}                              └─mTLS─► mita Exit (EU) ─► Интернет{m.NC}")
        m._box_row()
        role_str = (f"{m.GREEN}entry{m.NC} ({n_exits} exit-ов)" if role == "entry"
                     else f"{m.GREEN}exit{m.NC}" if role == "exit"
                     else f"{m.DIM}не настроен{m.NC}")
        m._box_kv("Роль:", role_str)
        m._box_row()
        m._box_item("1", "⬇  Настроить этот сервер как ENTRY (вход)")
        m._box_item("2", "⬆  Настроить этот сервер как EXIT (выход)")
        m._box_item("3", f"🧩  Управление Exit-нодами {m.DIM}({n_exits}){m.NC}")
        m._box_item("4", "🔄  Применить (конфиги+сервисы+правила+порты)")
        m._box_item("S", "⚖  Стратегия балансировки (6 режимов)")
        pin_lbl = ""
        if st.get("pinned_exit"):
            _pl = next((e.get("label") for e in st.get("exits", [])
                        if e["id"] == st["pinned_exit"]),
                       st["pinned_exit"])
            pin_lbl = f" {m.DIM}[{_pl}]{m.NC}"
        m._box_item("P", f"📌  Закрепить Exit-ноду{pin_lbl}")
        m._box_item("E", f"🧮  Состав балансировки "
                         f"{m.DIM}[{_lb_exits_summary(st)}]{m.NC}")
        m._box_item("5", "🏥  Health check + ребаланс")
        m._box_item("6", "📊  Статус")
        m._box_item("L", "🔗  Ссылки для клиентов (Karing/Nekobox/JSON/QR)")
        m._box_item("T", "🔔  TG-монитор каскада (алерты mita/Exit-ов/health-тика)")
        m._box_sep()
        m._box_item("7", "⏸  Деактивировать (правила+сервисы; данные сохранить)")
        m._box_item("8", f"{m.RED}🗑   Полное удаление{m.NC}")
        m._box_sep()
        m._box_item("Q", "← Назад в меню Mieru")
        m._box_bot(); print()

        try:
            ch = proto_ask(f"{m.CYAN}Выбор: {m.NC}", c=True).strip().lower()
        except ProtoCancelled:
            return

        if ch == "1":
            _setup_entry(st)
        elif ch == "2":
            _setup_exit(st)
        elif ch == "3":
            _manage_exits(st)
        elif ch == "4":
            if st.get("role") != "entry":
                print("  Сначала [1] (роль entry)."); m._pause(); continue
            if not st.get("exits"):
                print("  Нет Exit-ов — добавьте через [3]."); m._pause(); continue
            ok = _apply_all(st)
            print(f"  {'✓ применено' if ok else '⚠ применено с ошибками (см. выше)'}")
            if ok:
                # клиентская выдача сразу после успешного apply —
                # ссылки, по которым подключаются конечные клиенты
                _show_client_links(st)
            else:
                m._pause()
        elif ch == "s":
            _change_strategy(st)
        elif ch == "p":
            _change_pin(st)
        elif ch == "e":
            _change_lb_exits(st)
        elif ch == "5":
            r = health_tick(verbose=True)
            if not r.get("checked"):
                print("  Нет включённых Exit-ов.")
            m._pause()
        elif ch == "6":
            _show_status(st)
        elif ch == "l":
            _show_client_links(st, pick_user=True)
        elif ch == "t":
            from chimera.modules.mieru_cascade_monitor import do_cascade_monitor_menu
            do_cascade_monitor_menu()
        elif ch == "7":
            deactivate(st, keep_state=True)
            print("  Деактивировано (данные сохранены)."); m._pause()
        elif ch == "8":
            raw = proto_ask(f"  {m.YELLOW}Точно удалить mieru-cascade? [y/N]: {m.NC}",
                            default="N", c=True).strip().lower()
            if raw in ("y", "yes", "д", "да"):
                _full_uninstall(st)
                m._pause()
                return
        elif ch in ("q", ""):
            return
