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
  • Health-timer (*/2 мин): TCP-проба + E2E `mieru test` на каждый Exit;
    падение (2 подряд) исключает Exit из правил, восстановление возвращает.

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

Точка входа: из mieru.py (меню standalone-Mieru, пункт [C]) —
    from chimera.modules.mieru_cascade import do_mieru_cascade_menu
    do_mieru_cascade_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
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
        "strategy": "rr",          # rr | prio                    (entry)
        "strict_udp_block": False, # (entry)
        "exits": [],               # (entry)
        "exit": {},                # (exit-нода)
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


def _rule_specs(st: dict) -> list:
    """Все правила каскада. Формат: {"table","chain","rest"}.

    rest — argv после `-A/-D <chain>`. Порядок в nat OUTPUT: guard, затем
    statistic-правила по Exit-ам. Добавляются В КОНЕЦ OUTPUT (-A) — после
    существующих правил Chimera (TG-REDIRECT и пр. сохраняют приоритет).
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

    act = _active_exits(st)
    strategy = (st.get("strategy") or "rr").lower()
    n = len(act)
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


def _rules_apply(st: dict) -> bool:
    """Пересобирает правила каскада атомарно: удалить все свои → добавить."""
    specs = _rule_specs(st)
    # 1) удалить все известные нам правила (старый набор мог отличаться)
    for sp in _rule_specs_all_variants(st):
        while True:
            r = _run(_spec_argv(sp, add=False), capture=True)
            if r.returncode != 0:
                break
    # 2) добавить текущие
    ok = True
    for sp in specs:
        r = _run(_spec_argv(sp, add=True), capture=True)
        if r.returncode != 0:
            print(f"  [!] iptables: {r.stderr.strip()[:200] if r.stderr else '?'}")
            ok = False
    proto_ipt_persist()
    return ok


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
        for e in st.get("exits", []):
            rp = e.get("redsocks_port")
            if not rp:
                continue
            # statistic-вариант и чистый вариант (смена стратегии)
            for extra in (
                ["-m", "statistic", "--mode", "nth", "--every", "2", "--packet", "0"],
                ["-m", "statistic", "--mode", "nth", "--every", "3", "--packet", "0"],
                ["-m", "statistic", "--mode", "nth", "--every", "4", "--packet", "0"],
                [],
            ):
                _add({"table": "nat", "chain": "OUTPUT",
                      "rest": M + ["-p", "tcp"] + extra +
                      ["-j", "REDIRECT", "--to-ports", str(rp)]})
        _add({"table": "filter", "chain": "OUTPUT",
              "rest": M + ["-p", "udp", "!", "-d", "127.0.0.0/8",
                           "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]})
    return out


def _routing_sh_text(st: dict) -> str:
    """bash-скрипт пересборки правил при ребуте (генерируется из тех же
    спеков — единственный источник истины _rule_specs)."""
    lines = [
        "#!/bin/bash",
        "# mieru-cascade routing — регенерируется mieru_cascade.py при каждом apply",
        "# 1) зачистка своих правил (идемпотентно: restore из rules.v4 мог",
        "#    вернуть старый вариант после смены стратегии/strict_udp)",
    ]
    for sp in _rule_specs_all_variants(st):
        argv = _spec_argv(sp, add=False)
        lines.append("while " + " ".join(argv) +
                     " 2>/dev/null; do :; done")
    lines.append("# 2) добавить актуальные")
    for sp in _rule_specs(st):
        argv = " ".join(_spec_argv(sp, add=True))
        lines.append(argv + " || echo \"mieru-cascade: WARN: правило не добавлено\"")
    lines.append('echo "mieru-cascade routing applied (matcher=' +
                 str(st.get("matcher")) + ')"')
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


def _install_redsocks() -> bool:
    """redsocks через download manager (.deb из пула дистрибутива).

    Основной путь — PackageSpec (mieru_cascade_packages.py): ручное
    размещение /root → зеркала (yandex/ubuntu) → post_install dpkg -i.
    Fallback (все зеркала упали): apt-get с честным warn — это отступление
    от DM, но лучше работающий модуль, чем отказ установки.
    """
    if _redsocks_path():
        return True

    from chimera.modules.download_manager import fetch_package
    from chimera.modules.mieru_cascade_packages import (
        redsocks_candidates, redsocks_spec_for,
    )
    for fn in redsocks_candidates():
        spec = redsocks_spec_for(fn)
        if fetch_package(spec, print_hint_on_failure=False,
                         progress_label="redsocks"):
            if _redsocks_path():
                return True
    print("  [!] redsocks: зеркала DM не ответили — fallback apt-get "
          "(вне download manager)")
    r = _run(["apt-get", "install", "-y", "redsocks"], capture=True, timeout=180)
    return bool(_redsocks_path())


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
        "OnCalendar=*:0/2\n"
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
    pattern_cfg = _traffic_pattern_cfg()

    # 1) порты: выделить недостающим (однократно; свои — реюз)
    for e in st.get("exits", []):
        if not e.get("socks_port"):
            ports = _alloc_ports_for_exit(st, e.get("label", e["id"]))
            if not ports:
                print(f"  [!] не удалось выделить порты для {e['label']}")
                return False
            e.update(ports)

    # 2) конфиги инстансов + redsocks
    _write_units()
    for e in st.get("exits", []):
        _seed_hop_instance(e, pattern_cfg)
        (_ETC_DIR / f"redsocks-{e['id']}.conf").write_text(_redsocks_conf(e))

    # 3) правила iptables + routing.sh + персист
    ok_rules = _rules_apply(st)
    _ROUTING_SH.write_text(_routing_sh_text(st))
    _ROUTING_SH.chmod(0o755)

    # 4) сервисы
    for e in st.get("exits", []):
        for unit in (f"mieru-hop@{e['id']}", f"mieru-cascade-redsocks@{e['id']}"):
            _run(["systemctl", "enable", unit])
            _run(["systemctl", "restart", unit])
    for unit in ("mieru-cascade-routing", "mieru-cascade-health.timer"):
        _run(["systemctl", "enable", unit])
        _run(["systemctl", "restart", unit])

    state_save(st)
    return ok_rules


# ══════════════════════════════════════════════════════════════════════════════
#  НАСТРОЙКА РОЛЕЙ
# ══════════════════════════════════════════════════════════════════════════════

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

    # стратегия
    print(f"  {m.CYAN}Балансировка нескольких Exit-ов:{m.NC}")
    print(f"     {m.DIM}[1]{m.NC} rr  — round-robin по соединениям (по умолчанию)")
    print(f"     {m.DIM}[2]{m.NC} prio — active-backup (только первый живой)")
    raw = proto_ask(f"  {m.CYAN}Выбор [Enter=rr]: {m.NC}",
                    default="rr", c=True).strip().lower()
    strategy = "prio" if raw == "2" or raw == "prio" else "rr"

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

    users.append({"username": username, "password": password})
    mst["users"] = users

    _tp = mst.get("traffic_preset", "basic")
    cfg = m._build_server_config(
        users,
        mst.get("port_start", m._DEFAULT_PORT_START),
        mst.get("port_end", m._DEFAULT_PORT_END),
        mst.get("protocol", m._DEFAULT_PROTOCOL),
        traffic_pattern=m._MIERU_TRAFFIC_PRESETS.get(_tp, {}).get("config"),
    )
    err = m._apply_server_config(cfg)
    if err:
        print(f"  {m.RED}✗{m.NC} mita apply config: {err[:200]}"); m._pause(); return
    proto_save_state(m._MODULE_STATE, mst)
    _run(["systemctl", "reload-or-restart", m._SERVICE_NAME])

    st["role"] = "exit"
    st["exit"] = {
        "hop_username": username, "hop_password": password,
        "port_start": mst.get("port_start", m._DEFAULT_PORT_START),
        "port_end": mst.get("port_end", m._DEFAULT_PORT_END),
        "protocol": mst.get("protocol", m._DEFAULT_PROTOCOL),
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
    m._box_row()
    m._box_info("Перенесите эти данные на Entry (RU): меню Mieru → [C] →")
    m._box_info("[3] Управление Exit-нодами → Добавить.")
    m._box_bot()
    m._pause()


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
            m._box_row(f"  {state_ch}{m.NC} {i}. {m.YELLOW}{e['label']}{m.NC} "
                       f"→ {e['host']}:{e['port']}/{e['protocol']}"
                       f"{en}{lat}")
        m._box_row()
        m._box_item("1", "Добавить Exit")
        m._box_item("2", "Удалить Exit")
        m._box_item("3", "Вкл/выкл Exit")
        m._box_item("4", "Поднять в списке (приоритет для prio)")
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
        elif ch == "s":
            st["strict_udp_block"] = not st.get("strict_udp_block", False)
            state_save(st)
        elif ch in ("q", ""):
            return


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


def health_tick(verbose: bool = False) -> dict:
    """Проверка всех Exit-ов; при смене состояния — ребаланс правил."""
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
    if changed:
        result["changed"] = changed
        result["rebalanced"] = True
        _rules_apply(st)
        _ROUTING_SH.write_text(_routing_sh_text(st))
        if verbose:
            print(f"  {m.YELLOW}⟳{m.NC} правила перестроены: {', '.join(changed)}")
    state_save(st)
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
    proto_ipt_persist()


def deactivate(st: dict, keep_state: bool = True) -> None:
    """Снять правила, остановить сервисы. Exit-сторона: удалить hop-пользователя."""
    m = _mieru()
    role = st.get("role")
    if role == "entry":
        _stop_units(st)
        _strip_rules(st)
        _ROUTING_SH.unlink(missing_ok=True)
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
            if e.get("last_check"):
                m._box_row(f"     {m.DIM}проверка: {e['last_check']}{m.NC}")
        rules_now = sum(
            1 for sp in _rule_specs(st)
            if proto_ipt_rule_exists(sp["table"], sp["chain"], sp["rest"]))
        m._box_sep()
        m._box_kv("Правил в системе:", f"{rules_now}/{len(_rule_specs(st))}")
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
        m._box_item("5", "🏥  Health check + ребаланс")
        m._box_item("6", "📊  Статус")
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
            m._pause()
        elif ch == "5":
            r = health_tick(verbose=True)
            if not r.get("checked"):
                print("  Нет включённых Exit-ов.")
            m._pause()
        elif ch == "6":
            _show_status(st)
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
