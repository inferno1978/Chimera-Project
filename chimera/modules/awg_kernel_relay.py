"""
chimera/modules/awg_kernel_relay.py
───────────────────────────────────────────────────────────────────────────────
Kernel-relay: ОДИН туннель + userspace UDP-релей (обход двусторонней
блокировки «16к», кейс Виталия).

Кейс (дословно из чата, FAQ AWG_KERNEL_RELAY §1): «два туннеля с условиями
двусторонней блокировки 16к работать не будет. Причина: при согласовании
ключей в рамках туннеля требуется двусторонний обмен, а его нет — проходят
только первые 25 пакетов в каждую из сторон и потом блок. Блок может пробить
только инициатор при помощи отправки i1 — а это происходит только в одну
сторону, а надо и в обратную». Патент-схема Виталия: «туннель остаётся 1,
но добавляется модуль ретрансляции, который устанавливает второе соединение
в рамках 1 туннеля и пробивает блок в обратную сторону» (боевой пилот,
~сутки в проде у автора кейса; датаграмма для пробоя — от DNS-запроса).

Схема (транспорт для ОДНОГО выделенного kernel AWG-пира, ставится на
ОБЕИХ нодах линка — обычно awg1 каскада):

    kernel awg1 (A) ──► 127.0.0.1:loopA ──► relay A
                                            │ tx-флоу: A.addr:A.tx ──► B:B.rx
                                            │ (первая датаграмма флоу — DNS,
                                            │  DPI берёт флоу в белый список)
                                            ▼
                                       relay B ──► 127.0.0.1:kernelB ──► kernel awg1 (B)
                                       relay B ◄── … ◄── tx-флоу B (сеется
                                                       прелеюдией на B)

Физика:
  • Kernel AWG продолжает видеть «пира» на 127.0.0.1:loop — этот флоу
    не режется никогда. Релей — тупой датаграммный насос между localhost
    и парой внешних UDP-сокетов.
  • КАЖДОЕ направление едет по СВОЕМУ wire-флоу, и КАЖДЫЙ отправитель
    СЕЕТ свой флоу валидной DNS-датаграммой (прелеюдией): DPI решает по
    первому пакету флоу — «DNS» → белый список → WG-пакеты (handshake,
    keepalive, данные) едут дальше по завайллистнутому флоу ВЕЗДЕ.
  • Туннель, ключи, обфускация, маршрутизация транзита, клиенты —
    НЕИЗМЕННЫ: меняется только проводной транспорт endpoint'а.

Ключевые инварианты (канон пилота Виталия + канон проекта):
  • Runtime-endpoint переключается ТОЛЬКО у выделенного kernel AWG-пира
    с одним peer и уже известным прямым IPv4 endpoint (awg show userspace,
    пустые/loopback endpoint'ы и multi-peer отказ).
  • Guarded-откат: restore_endpoint сверяет ifindex/listen-port/pubkey
    и текущий endpoint — откат ЧУЖОГО endpoint запрещён, запись
    сохраняется для разбора.
  • Запись состояния публикуется атомарно (os.link — os.rename поверх
    существующего билета невозможен).
  • EPERM на send данных отбрасывает только эту датаграмму (журнал —
    раз в минуту на направление); EPERM на прелюдии блокирует выход до
    вмешательства оператора; вход остаётся рабочим.
  • Прелюдия-пресеты (кастомизация): боевой DNS example.com (фикс-txid),
    DNS random-txid, свой домен, raw-hex, none — + refresh-интервал
    (пере-сеять флоу при простое; 0 = выкл).
  • Watchdog (минутный тик, канон awg-split-direction): handshake-флоу
    жив (rekey+keepalive) → дёшево; юнит/флоу умер → relaunch юнита;
    N неудач подряд → авто-откат на прямой endpoint + TG — ЛИБО, по
    выбору оператора (fail_action=notify_only, фичареквест Виталия
    26.11 «уведомлять, но не откатывать»), только TG-уведомление без
    отката: режим держится, relaunch продолжается каждую минуту,
    напарник вернётся — флоу оживёт сам.
  • Автовосстановление после ребута — ОПЦИЯ (default off, честные
    границы канона: transient-юниты и /run-записи не переживают ребут).

Уведомления (tg_notify_event, канон каскадных событий):
  awg_relay_on        — релей включён (endpoint → loop)
  awg_relay_dir_dead  — флоу умирал, relaunch спас / не помог (попытка N)
  awg_relay_off       — выключен (вручную / авто-откат / потерян после ребута)
  awg_relay_hold      — notify-only: лестница relaunch исчерпана, откат
                        отключён — режим на удержании (один раз)
  awg_relay_recovered — notify-only: флоу ожил после удержания
                        (напарник вернулся)
"""
from __future__ import annotations

import errno
import json
import os
import select
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid
from contextlib import ExitStack
from pathlib import Path
from typing import Optional

# ────────────────────────────────────────────────────────────────────────────
#  ЧАСТЬ 1. WORKER (чистый stdlib — запускается systemd-run'ом как
#  `python3 -I -B <этот файл> <cfg-json>`; НЕ импортирует chimera.*)
# ────────────────────────────────────────────────────────────────────────────

# Один протокол-лог на направление в минуту: EPERM-шторм не затопит журнал.
_last_log: dict = {}

# Символ «выход заблокирован» (EPERM на прелюдии): выход стоит, вход жив.
BLOCKED = object()


def send_data(sock, data, direction):
    """Отправка с честной EPERM-семантикой (канон пилота).

    EPERM ≠ фатал: датаграмма теряется (та и только та), worker живёт —
    оператор видит жалобу в journalctl не чаще раза в минуту.
    Любая другая OSError — честное исключение вверх.
    """
    try:
        sock.send(data)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise
        now = time.monotonic()
        if now >= _last_log.get(direction, float("-inf")):
            print("relay: EPERM " + direction, file=sys.stderr, flush=True)
            _last_log[direction] = now + 60
        return False
    return True


def outbound(tx, data, first):
    """Локальный (kernel→wire) датаграммный ход.

    `first` — несбитая прелюдия флоу: уходит ПЕРВОЙ датаграммой, затем
    payload. BLOCKED — выход умер (прелеюдию зарубили): данные молча
    теряются, вход продолжает качать.
    """
    if first is BLOCKED:
        return BLOCKED
    if first is not None and not send_data(tx, first, "prelude; output disabled"):
        return BLOCKED
    send_data(tx, data, "kernel-to-wire")
    return None


def pump(local, tx, rx, first, timeout=None):
    """Один select-ход насоса (канон пилота, без изменений по сути).

    local (127.0.0.1:loop ↔ kernel) читает датаграммы ядра и качает их
    в tx (wire); rx (wire) читает датаграммы напарника и качает в local.
    Возвращает актуальный `first` (прелеюдию), т.к. отправить её обязан
    ровно один раз ДО первого payload.
    """
    for src in select.select([local, rx], [], [], timeout)[0]:
        try:
            data = src.recv(65535)
            if src is local:
                first = outbound(tx, data, first)
            else:
                send_data(local, data, "wire-to-kernel")
        except (ConnectionRefusedError, ConnectionResetError):
            continue
    return first


def worker(cfg):
    """Точка входа worker'а (запускается ТОЛЬКО как __main__ из systemd).

    cfg (JSON-аргумент argv[1]):
      loop/kernel/tx/rx      — UDP-порты localhost-пары и wire-пары;
      addr                    — локальный IPv4 внешнего интерфейса;
      peer                    — IPv4 напарника;
      remote_tx/remote_rx    — wire-порты НАПАРНИКА;
      prelude                 — hex прелюдии ("" = без прелюдии);
      refresh                 — секунды пере-сева флоу при простое (0 = выкл).

    Refresh: DPI-таблицы флоу живут ограниченно; при простое туннеля
    (нет keepalive) пере-сеем прелеюдию раз в N секунд — «DNS-активный»
    флоу не выпадает из белого списка.
    """
    prelude = bytes.fromhex(cfg.get("prelude") or "")
    refresh = float(cfg.get("refresh") or 0)
    with ExitStack() as stack:

        def pair(addr, port, dest, dport):
            s = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            s.bind((addr, port))
            s.connect((dest, dport))
            return s

        local = pair("127.0.0.1", cfg["loop"], "127.0.0.1", cfg["kernel"])
        tx = pair(cfg["addr"], cfg["tx"], cfg["peer"], cfg["remote_rx"])
        rx = pair(cfg["addr"], cfg["rx"], cfg["peer"], cfg["remote_tx"])
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
            path = os.environ["NOTIFY_SOCKET"]
            notify.connect("\0" + path[1:] if path.startswith("@") else path)
            notify.send(b"READY=1")
        first = prelude if prelude else None
        seeded_at = time.monotonic() if prelude else 0.0
        while True:
            first = pump(local, tx, rx, first,
                         timeout=(1.0 if refresh and prelude else None))
            if refresh and prelude and time.monotonic() - seeded_at >= refresh:
                if first is not BLOCKED:
                    send_data(tx, prelude, "prelude-refresh")
                seeded_at = time.monotonic()


# ────────────────────────────────────────────────────────────────────────────
#  ЧАСТЬ 2. ПРЕЛЮДИИ (чистый stdlib; пресеты = кастомизация модуля)
# ────────────────────────────────────────────────────────────────────────────

def relay_prelude_dns(domain: str, txid: Optional[int] = None,
                      flags: int = 0x0120, qtype: int = 1) -> bytes:
    """Валидный DNS-запрос (A/IN) — прелюдия флоу.

    DPI классифицирует флоу по ПЕРВОМУ пакету; DNS-запрос — белый список.
    domain="example.com", txid=0x67c2, flags=0x0120 дают РОВНО боевые
    байты пилота Виталия (см. тест: test_prelude_fixed_matches_pilot).
    """
    import random
    if txid is None:
        txid = random.getrandbits(16)
    labels = [p for p in domain.strip(".").split(".") if p]
    # метка: ≤63 симв, только буквы/цифры/дефис (строгий DNS-алфавит;
    # strip по разрешённому набору оставляет хвост = есть чужой символ)
    if not labels or any(
            len(p) > 63 or p.strip(
                "-abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
            for p in labels):
        raise ValueError(f"Некорректное DNS-имя: {domain!r}")
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in labels) + b"\x00"
    return (struct.pack(">HHHHHH", txid & 0xFFFF, flags, 1, 0, 0, 0)
            + qname + struct.pack(">HH", qtype, 1))


# Боевые байты пилота (example.com A/IN, txid 0x67c2) — фикс-эталон
# пресета dns-fixed и тестов.
RELAY_PRELUDE_PILOT_HEX = (
    "67c201200001000000000000076578616d706c6503636f6d0000010001")

# Пресеты прелюдии: name → (метка меню, чем живёт, генератор).
# Генератору передаются domain/hex из бокса настроек.
RELAY_PRELUDE_PRESETS: dict = {
    "dns-fixed": {
        "label": "DNS example.com, фикс-txid (боевой пилот Виталия)",
        "desc": "Ровно датаграмма пилота: валидный DNS-запрос example.com "
                "A/IN. Повторяемость конфигурации — свечной приоритет.",
    },
    "dns-rand": {
        "label": "DNS example.com, случайный txid",
        "desc": "Та же датаграмма, но txid свежий на каждое включение: "
                "повторный seed не выглядит дублем одного запроса.",
    },
    "custom-domain": {
        "label": "DNS своего домена",
        "desc": "Свой домен (одна метка которого реально существует у вас) — "
                "запрос выглядит как резолв вашего ресурса.",
    },
    "custom-hex": {
        "label": "Raw hex (свои байты)",
        "desc": "Точная датаграмма hex'ом — для экспериментов с «портретом "
                "поля» (снимок рабочего запроса tcpdump'ом).",
    },
    "none": {
        "label": "Без прелюдии",
        "desc": "Чистый релей: флоу сеет первый WG-пакет. Поле, режущее "
                "только «непервыe» датаграммы, может пропустить и так.",
    },
}


def relay_prelude_build(preset: str, domain: str = "",
                        hex_data: str = "") -> bytes:
    """Пресет → байты прелюдии (единая точка правды меню/тестов).

    Некорректный пресет — ValueError (не молчалимый фолбэк: конфиг
    должен быть предсказуем, канон «честных границ»).
    """
    if preset == "dns-fixed":
        return bytes.fromhex(RELAY_PRELUDE_PILOT_HEX)
    if preset == "dns-rand":
        return relay_prelude_dns(domain or "example.com")
    if preset == "custom-domain":
        if not domain:
            raise ValueError("custom-domain: домен обязателен")
        return relay_prelude_dns(domain)
    if preset == "custom-hex":
        if not hex_data:
            raise ValueError("custom-hex: hex-датаграмма обязательна")
        try:
            return bytes.fromhex(hex_data.replace(" ", ""))
        except ValueError as exc:
            raise ValueError(f"custom-hex: не hex ({exc})") from exc
    if preset == "none":
        return b""
    raise ValueError(f"Неизвестный пресет прелюдии: {preset!r}")


# ────────────────────────────────────────────────────────────────────────────
#  ЧАСТЬ 3. RUNTIME (менеджмент юнитом/endpoint'ом; chimera-импорты —
#  ЛЕНИВЫЕ, чтобы worker-часть оставалась запускаемой через python3 -I)
# ────────────────────────────────────────────────────────────────────────────

def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _notify(event: str, detail: str) -> None:
    """Best-effort TG-уведомление (не бросает — канон каскада)."""
    try:
        from .tg_bot import tg_notify_event
        tg_notify_event(event, detail)
    except Exception:
        pass


def run(*args):
    """check_output-обёртка для awg/ip/systemctl-команд (канон пилота)."""
    return subprocess.check_output(args, text=True, timeout=30).strip()


def _iface_name_valid(iface: str) -> bool:
    import re
    return bool(re.fullmatch(r"awg[0-9]{1,12}", iface or ""))


def snapshot(iface):
    """(identity, endpoint) выделенного kernel AWG-пира.

    identity = [ifindex, listen-port, pubkey] — телеметрия guarded-отката;
    endpoint — текущий runtime-endpoint пира (ровно один пир: multi-peer
    и пустой вывод — честный отказ).
    """
    (link,) = json.loads(run("ip", "-d", "-j", "link", "show", "dev", iface))
    if link["linkinfo"]["info_kind"] != "amneziawg":
        raise ValueError("Не kernel AmneziaWG")
    (row,) = run("awg", "show", iface, "endpoints").splitlines()
    key, endpoint = row.split()
    return [
        link["ifindex"],
        int(run("awg", "show", iface, "listen-port")),
        key,
    ], endpoint


def set_endpoint(st, endpoint):
    run("awg", "set", st["iface"], "peer", st["identity"][2],
        "endpoint", endpoint)


def restore_endpoint(st):
    """Guarded-откат на прямой endpoint (сердце безопасности пилота).

    Сверки: identity (ifindex/listen-port/pubkey) и текущий endpoint
    (target|old). Любой дрейф = «интерфейс, пир или endpoint изменился» —
    откат ЧУЖОГО endpoint запрещён, запись остаётся для разбора.
    """
    ident, endpoint = snapshot(st["iface"])
    if ident != st["identity"] or endpoint not in (st["target"], st["old"]):
        raise ValueError(
            "Интерфейс, peer или endpoint изменился. Автооткат запрещён; "
            "запись сохранена.")
    if endpoint != st["old"]:
        set_endpoint(st, st["old"])
        if snapshot(st["iface"]) != (ident, st["old"]):
            raise ValueError("Откат endpoint не подтверждён")


def unit_status(st):
    """Статус transient-юнита; «absent» ≠ ошибка шины (rc=4 = юнит выгружен).

    Гварды принадлежности: Description == имя юнита и Transient=yes —
    коллизия имени с НЕ нашим юнитом = ValueError, а не ложный статус.
    """
    unit = st["unit"]
    p = subprocess.run(
        [
            "systemctl", "show", unit,
            "-p", "LoadState", "-p", "Description",
            "-p", "ActiveState", "-p", "Transient",
        ],
        capture_output=True, text=True, timeout=10,
    )
    fields = dict(l.split("=", 1) for l in p.stdout.splitlines() if "=" in l)
    if p.returncode in (0, 4) and fields.get("LoadState") == "not-found":
        return "absent"
    if (
        p.returncode
        or fields.get("Transient") != "yes"
        or fields.get("Description") != unit
    ):
        raise ValueError("Не удалось подтвердить принадлежность службы")
    return fields["ActiveState"]


def port(v):
    n = int(v)
    if not 1 <= n <= 65535:
        raise ValueError("Недопустимый UDP-порт")
    return n


def address(value):
    from ipaddress import IPv4Address
    ip = IPv4Address(value)
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or int(ip) == 0xFFFFFFFF:
        raise ValueError("Нужен unicast IPv4 транспортной сети")
    return str(ip)


# ── state (бокс в awg_standalone_state.json — переживает ребут) ───────────

def relay_state_get(state: Optional[dict] = None) -> dict:
    """Бокс kernel_relay из state (пустой dict = не настроен)."""
    from .awg_constants import AWGS_RELAY_STATE_KEY
    from .awg_state import awgs_state_load
    if state is None:
        state = awgs_state_load()
    box = state.get(AWGS_RELAY_STATE_KEY) or {}
    return box if isinstance(box, dict) else {}


def relay_is_on(state: Optional[dict] = None) -> bool:
    return bool(relay_state_get(state).get("enabled"))


def _fail_action_norm(value) -> str:
    """Нормализация fail_action — поведения watchdog при исчерпании
    relaunch-лестницы (AWGS_RELAY_FAIL_ACTIONS).

    Чужие/отсутствующие значения → «rollback» — честная обратная
    совместимость старых state-боксов (без поля = прежний откат).
    """
    from .awg_constants import AWGS_RELAY_FAIL_ACTIONS
    return value if value in AWGS_RELAY_FAIL_ACTIONS else "rollback"


def _relay_state_update(mutate) -> bool:
    """Read-modify-write бокса с честным результатом сохранения (канон
    register_exit FIX 09.11: молчаливая потеря = враньё success)."""
    from .awg_constants import AWGS_RELAY_STATE_KEY
    from .awg_state import awgs_state_load, awgs_state_save
    state = awgs_state_load()
    box = relay_state_get(state)
    mutate(box)
    state[AWGS_RELAY_STATE_KEY] = box
    return awgs_state_save(state)


def _worker_cfg(cfg: dict) -> dict:
    """Подмножество cfg для worker'а (только то, что читает worker())."""
    return {
        "loop": int(cfg["loop"]), "kernel": int(cfg["kernel"]),
        "tx": int(cfg["tx"]), "rx": int(cfg["rx"]),
        "remote_tx": int(cfg["remote_tx"]), "remote_rx": int(cfg["remote_rx"]),
        "addr": cfg["addr"], "peer": cfg["peer"],
        "prelude": cfg.get("prelude") or "",
        "refresh": int(cfg.get("refresh") or 0),
    }


def relay_unit_launch(cfg: dict, unit: str) -> bool:
    """systemd-run transient-юнита с хардненингом (канон пилота).

    DynamicUser + капы только CAP_NET_BIND_SERVICE (порт < 1024 — 443/53),
    restricted AF_INET/AF_UNIX, Type=notify (worker шлёт READY=1).
    """
    argv = [
        "systemd-run", "--collect",
        "--unit=" + unit, "--description=" + unit,
        "-p", "Type=notify",
        "-p", "TimeoutStartSec=10s",
        "-p", "DynamicUser=yes",
        "-p", "NoNewPrivileges=yes",
        "-p", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "-p", "AmbientCapabilities=CAP_NET_BIND_SERVICE",
        "-p", "RestrictAddressFamilies=AF_INET AF_UNIX",
        "/usr/bin/python3", "-I", "-B",
        str(Path(__file__).resolve()),
        json.dumps(_worker_cfg(cfg), separators=(",", ":")),
    ]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    return p.returncode == 0


def relay_enable(cfg: dict) -> tuple:
    """Включает релей на ЭТОЙ ноде. Возвращает (ok, reason).

    cfg: iface, addr, loop, tx, rx, remote_tx, remote_rx (+ prelude-поля
    preset/domain/hex_data, refresh). Лестница (канон пилота):
      валидация → снимок endpoint'а → атомарная публикация записи →
      systemd-run юнита → сверка юнита и endpoint'а → переключение
      kernel endpoint на 127.0.0.1:loop → подтверждение → state + TG.
    Любой провал на лестнице = полный откат (disable) — туннель
    возвращается на прямой endpoint, пользователи ничего не замечают.
    """
    from .awg_constants import AWGS_RELAY_ROOT
    core = _core_module()

    iface = cfg.get("iface", "")
    if not _iface_name_valid(iface):
        return False, f"Ожидается имя awgN, получено {iface!r}"

    # Каталог состояния — root:0700 (канон пилота; /run tmpfs)
    try:
        AWGS_RELAY_ROOT.mkdir(mode=0o700, exist_ok=True)
        st = AWGS_RELAY_ROOT.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
                or stat.S_IMODE(st.st_mode) != 0o700):
            return False, "Небезопасный каталог состояния /run/chimera-kernel-relay"
    except OSError as exc:
        return False, f"Каталог состояния: {exc}"

    try:
        ident, old = snapshot(iface)
    except (ValueError, KeyError, subprocess.SubprocessError) as exc:
        return False, (f"Снимок {iface} не удался: {exc} — нужен живой "
                       "kernel AWG с ровно одним peer и прямым IPv4 endpoint")

    host, sep, number = old.rpartition(":")
    if not sep:
        return False, ("Нужен ранее установленный прямой IPv4 endpoint "
                       "для отката (пустой/loopback недопустим)")
    try:
        peer = address(host)
        port(number)
    except ValueError as exc:
        return False, f"Endpoint {old}: {exc}"

    try:
        full = dict(
            kernel=int(ident[1]), peer=peer,
            addr=address(cfg["addr"]),
            loop=port(cfg["loop"]), tx=port(cfg["tx"]), rx=port(cfg["rx"]),
            remote_tx=port(cfg["remote_tx"]), remote_rx=port(cfg["remote_rx"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"Порты/адрес: {exc}"
    if len({full[k] for k in ("loop", "tx", "rx", "kernel")}) != 4:
        return False, "Порты конфликтуют (loop/tx/rx/kernel обязаны различаться)"
    if full["remote_tx"] == full["remote_rx"]:
        return False, "Порты напарника (remote_tx/remote_rx) совпадают"
    if full["addr"] == full["peer"]:
        return False, "Локальный адрес совпадает с пиром"

    try:
        (route,) = json.loads(
            run("ip", "-j", "route", "get", full["peer"], "from", full["addr"]))
        if route.get("dev") in ("lo", iface):
            return False, "Нужен отдельный внешний маршрут (не lo/сам awg)"
    except (ValueError, subprocess.SubprocessError) as exc:
        return False, f"Маршрут до пира: {exc}"

    try:
        prelude = relay_prelude_build(cfg.get("preset", "dns-fixed"),
                                      cfg.get("domain", ""),
                                      cfg.get("hex_data", ""))
    except ValueError as exc:
        return False, f"Прелюдия: {exc}"
    cfg = dict(cfg)
    cfg.update(full)
    cfg["prelude"] = prelude.hex() if prelude else ""

    unit = "chimera-awg-relay-" + uuid.uuid4().hex + ".service"
    target = f"127.0.0.1:{full['loop']}"
    record = AWGS_RELAY_ROOT / (iface + ".json")
    rec = dict(iface=iface, identity=ident, old=old, target=target, unit=unit)

    if snapshot(iface) != (ident, old):
        return False, "AWG изменился до запуска"

    # Атомарная публикация билета (os.link: os.rename поверх чужого
    # существующего билета невозможен — канон пилота).
    temp = record.with_suffix("." + uuid.uuid4().hex)
    try:
        with temp.open("x") as f:
            json.dump(rec, f)
            f.flush()
            os.fsync(f.fileno())
        os.link(temp, record)
    except OSError as exc:
        return False, f"Публикация записи: {exc}"
    finally:
        temp.unlink(missing_ok=True)

    try:
        if not relay_unit_launch(cfg, unit):
            raise ValueError("systemd-run юнита не удался")
        current, endpoint = snapshot(iface)
        if (current != ident or endpoint not in (old, target)
                or unit_status(rec) != "active"):
            raise ValueError("Служба или AWG не готовы")
        set_endpoint(rec, target)
        if snapshot(iface) != (ident, target):
            raise ValueError("Переключение endpoint не подтверждено")
    except BaseException as exc:
        try:
            relay_disable(iface=cfg.get("iface"), reason=str(exc))
        except Exception as exc2:
            core.log_to_file(
                "WARN", f"relay_disable после провала тоже упал: {exc2}")
        return False, f"Запуск релея: {exc}"

    ok = _relay_state_update(lambda b: b.update({
        "enabled": True, "iface": iface, "unit": unit,
        "endpoint_old": old, "endpoint_target": target,
        "addr": full["addr"], "peer": full["peer"],
        "ports": {"loop": full["loop"], "tx": full["tx"], "rx": full["rx"],
                  "remote_tx": full["remote_tx"], "remote_rx": full["remote_rx"]},
        "kernel": full["kernel"],
        "preset": cfg.get("preset", "dns-fixed"),
        "prelude_hex": cfg["prelude"],
        "refresh": int(cfg.get("refresh") or 0),
        "restore_on_boot": bool(cfg.get("restore_on_boot")),
        "fail_action": _fail_action_norm(cfg.get("fail_action")),
        "fail_count": 0,
        "applied_at": _now_iso(),
    }))
    if not ok:
        core.log_to_file("WARN", "relay_enable: state НЕ сохранён")
    _notify("awg_relay_on",
            f"AWG kernel-relay включён: {iface} endpoint → {target}; "
            f"флоу {full['addr']}:{full['tx']} → {full['peer']}:"
            f"{full['remote_rx']} (прелеюдия: "
            f"{cfg.get('preset', 'dns-fixed')})")
    return True, ""


def relay_disable(reason: str = "", auto: bool = False,
                  iface: Optional[str] = None) -> bool:
    """Выключает релей на ЭТОЙ ноде (guarded, канон пилота).

    Первоисточник отката — /run-запись (в ней identity/old/target/unit);
    iface берётся из параметра → бокса state → авто-поиска единственной
    записи (выживание отката НЕ должно зависеть от state-файла).
    Стоп юнита → guarded-восстановление прямого endpoint → снятие записи
    → state box enabled=False + TG.
    При невозможности guarded-отката поднимает ValueError (запись
    сохраняется для разбора — молчаливый откат чужого endpoint запрещён).
    /run-записи нет (ребут/чистка) — endpoint уже прямой по конфигу:
    чистим state и уведомляем (аварийного отката не требуется).
    """
    from .awg_constants import AWGS_RELAY_ROOT
    core = _core_module()

    box = relay_state_get()
    if iface is None:
        iface = box.get("iface")
    if iface is None:
        try:
            records = sorted(AWGS_RELAY_ROOT.glob("awg*.json"))
        except OSError:
            records = []
        if len(records) == 1:
            iface = records[0].stem
        elif len(records) > 1:
            raise ValueError("Несколько записей релея — отключайте по iface")
    if iface is None and not box:
        return True  # включения не было вовсе — честный no-op

    record = AWGS_RELAY_ROOT / (iface + ".json") if iface else None
    if record is not None and record.exists():
        rec = json.loads(record.read_text())
        status = unit_status(rec)
        if status != "absent":
            run("systemctl", "stop", rec["unit"])
            if unit_status(rec) not in ("inactive", "absent", "failed"):
                raise ValueError("Служба не остановилась")
        restore_endpoint(rec)
        record.unlink()
    else:
        # Записи нет (ребут/чистка tmpfs): endpoint уже прямой по конфигу;
        # transient-юнит тоже не пережил ребут — глухой stop по имени из
        # бокса на всякий случай (guarded-свирок нет — best-effort).
        unit = box.get("unit")
        if unit:
            core._run(["systemctl", "stop", unit], check=False, quiet=True)

    ok = _relay_state_update(lambda b: b.update({
        "enabled": False,
        "disabled_at": _now_iso(),
        "disabled_reason": reason,
    }))
    if not ok:
        core.log_to_file("WARN", "relay_disable: state НЕ сохранён")
    _notify("awg_relay_off",
            ("AWG kernel-relay ОТКЛЮЧЁН (авто-откат) — прямой endpoint "
             "восстановлен" if auto else
             "AWG kernel-relay выключен вручную — прямой endpoint "
             "восстановлен")
            + (f". Причина: {reason}" if reason else ""))
    return True


# ────────────────────────────────────────────────────────────────────────────
#  ЧАСТЬ 4. WATCHDOG (канон awg-split-direction: минутный тик)
# ────────────────────────────────────────────────────────────────────────────

def relay_iface_probe(iface: str) -> dict:
    """Показания kernel AWG-пира: handshake age + transfer (канон
    link_parse_awg_show из awg_link_probe)."""
    from .awg_link_probe import link_parse_awg_show
    p = subprocess.run(["awg", "show", iface],
                        capture_output=True, text=True, check=False)
    if p.returncode != 0:
        return {"up": False, "handshake_age": None, "tx": 0, "rx": 0}
    data = link_parse_awg_show(p.stdout or "")
    data["up"] = True
    return data


def relay_handshake_alive(probe: dict) -> bool:
    from .awg_constants import AWGS_RELAY_STALE_SEC
    age = probe.get("handshake_age")
    return age is not None and age <= AWGS_RELAY_STALE_SEC


def relay_relaunch(box: dict) -> tuple:
    """Relaunch worker'а БЕЗ переключения endpoint (endpoint уже loop).

    Новый transient-юнит (systemd-run --collect выгружает мёртвые), запись
    и state обновляются — флоу сеется заново (свежий DPI-бюджет флоу).
    """
    from .awg_constants import AWGS_RELAY_ROOT
    iface = box.get("iface", "")
    record = AWGS_RELAY_ROOT / (iface + ".json")
    if not record.exists():
        return False, "запись /run отсутствует"
    rec = json.loads(record.read_text())
    ports = box.get("ports") or {}
    cfg = dict(
        iface=iface, addr=box.get("addr"), peer=box.get("peer"),
        kernel=box.get("kernel"),
        loop=ports.get("loop"), tx=ports.get("tx"), rx=ports.get("rx"),
        remote_tx=ports.get("remote_tx"), remote_rx=ports.get("remote_rx"),
        prelude=box.get("prelude_hex", ""),
        refresh=box.get("refresh", 0),
        preset=box.get("preset", "dns-fixed"),
    )
    unit = "chimera-awg-relay-" + uuid.uuid4().hex + ".service"
    if not relay_unit_launch(cfg, unit):
        return False, "systemd-run не удался"
    rec["unit"] = unit
    temp = record.with_suffix("." + uuid.uuid4().hex)
    try:
        with temp.open("x") as f:
            json.dump(rec, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, record)
    except OSError as exc:
        return False, f"обновление записи: {exc}"
    finally:
        temp.unlink(missing_ok=True)
    _relay_state_update(lambda b: b.update({"unit": unit}))
    return True, ""


def relay_health_tick() -> str:
    """Health-тик watchdog'а (таймер раз в минуту, канон split_health_tick).

    Возвращает строку-действие (для логов/тестов):
      off            — режим выключен
      ok             — флоу жив (handshake свеж: rekey+keepalive дышат)
      relaunch:<why> — юнита/записи не было — подняли заново (ребут)
      lost           — записи нет, автовосстановление выключено: state
                       почищен, TG отправлен
      recovered      — флоу умирал, relaunch юнита спас
      pending-N      — после relaunch флоу всё ещё мёртв (неудача N/LIMIT)
      rollback       — лестница исчерпана: авто-откат на прямой endpoint
      hold-N         — notify-only (fail_action): лестница исчерпана, откат
                       отключён — режим на удержании, relaunch продолжается
                       (напарник вернётся — флоу оживёт, TG сообщит)
    """
    from .awg_constants import (AWGS_RELAY_ROOT, AWGS_RELAY_FAIL_LIMIT)
    core = _core_module()

    box = relay_state_get()
    if not box.get("enabled"):
        return "off"

    iface = box.get("iface", "")
    record = AWGS_RELAY_ROOT / (iface + ".json")

    # /run-записи нет: ребут/чистка tmpfs. Endpoint у ядра — прямой (по
    # конфигу). Автовосстановление (default off) = полный re-enable из cfg.
    if not record.exists():
        if not box.get("restore_on_boot"):
            core.log_to_file(
                "WARN", "relay_health_tick: записи /run нет, "
                        "автовосстановление выключено — снимаю режим")
            try:
                relay_disable(reason="юнит потерян после ребута; "
                                     "автовосстановление выключено")
            except Exception as exc:
                core.log_to_file("WARN", f"relay_disable: {exc}")
            _notify("awg_relay_off",
                    "AWG kernel-relay: юнит потерян после ребута, "
                    "автовосстановление выключено — режим снят "
                    "(endpoint и так прямой по конфигу)")
            return "lost"
        ports = box.get("ports") or {}
        cfg = dict(
            iface=iface, addr=box.get("addr"), peer=box.get("peer"),
            kernel=box.get("kernel"),
            loop=ports.get("loop"), tx=ports.get("tx"), rx=ports.get("rx"),
            remote_tx=ports.get("remote_tx"),
            remote_rx=ports.get("remote_rx"),
            prelude=box.get("prelude_hex", ""),
            refresh=box.get("refresh", 0),
            preset=box.get("preset", "dns-fixed"),
            restore_on_boot=True,
        )
        ok, why = relay_enable(cfg)
        if not ok:
            core.log_to_file("ERROR",
                             f"relay_health_tick: автовосстановление "
                             f"не удалось: {why}")
        return "relaunch:boot" if ok else f"relaunch-failed:{why}"

    rec = json.loads(record.read_text())

    # Дешёвый тик: юнит жив и handshake свеж → флоу дышит (rekey ~2 мин +
    # keepalive 25 с держат возраст заметно ниже stale-порога).
    try:
        unit_alive = unit_status(rec) == "active"
    except (ValueError, subprocess.SubprocessError) as exc:
        core.log_to_file("WARN", f"relay_health_tick: unit_status: {exc}")
        unit_alive = False
    probe = relay_iface_probe(iface)

    if unit_alive and relay_handshake_alive(probe):
        prev_fail = int(box.get("fail_count") or 0)
        if prev_fail:
            # notify-only: флоу ожил ПОСЛЕ удержания (напарник вернулся)
            # — сообщаем восстановление: hold-уведомление было, ответ на
            # него обязан быть, иначе владелец вечно гадает, ожил линк
            # или нет (rollback-режиму это не нужно — там режима уже нет).
            if (prev_fail >= AWGS_RELAY_FAIL_LIMIT
                    and _fail_action_norm(box.get("fail_action"))
                    == "notify_only"):
                _notify("awg_relay_recovered",
                        f"AWG kernel-relay: флоу ОЖИЛ ({iface}) после "
                        f"удержания ({prev_fail} неудач) — handshake "
                        f"свеж, режим не откатывался (notify-only)")
            _relay_state_update(lambda b: b.update({"fail_count": 0}))
        return "ok"

    # Флоу/юнит мёртв: relaunch (новый юнит = новый флоу = свежий DPI-бюджет)
    why = "unit" if not unit_alive else "handshake"
    ok, reason = relay_relaunch(box)
    if not ok:
        core.log_to_file("ERROR", f"relay_health_tick: relaunch: {reason}")
    _time_sleep_wrapper(5)
    probe2 = relay_iface_probe(iface)
    if relay_handshake_alive(probe2):
        _relay_state_update(lambda b: b.update(
            {"fail_count": 0, "last_recovered": _now_iso()}))
        _notify("awg_relay_dir_dead",
                f"AWG kernel-relay: флоу умирал ({why}), relaunch юнита "
                f"спас ({iface})")
        return "recovered"

    fail = int(box.get("fail_count") or 0) + 1
    action = _fail_action_norm(box.get("fail_action"))
    core.log_to_file(
        "ERROR",
        f"relay_health_tick: флоу мёртв после relaunch ({why}), "
        f"неудача #{fail}/{AWGS_RELAY_FAIL_LIMIT}"
        + (" [notify-only: держим]" if action == "notify_only" else ""))

    if action == "notify_only":
        # Фичареквест Виталия (26.11): «уведомлять, но не откатывать» —
        # прямой endpoint в кейсах двусторонней блокировки всё равно
        # мёртв, а откат после ребута/долгого простоя напарника требовал
        # бы ручного восстановления режима. Держим: relaunch продолжается
        # каждую минуту (новый юнит = свежий DPI-бюджет флоу), напарник
        # вернётся — handshake оживёт сам. TG-срез по спаму: до предела —
        # dir_dead по попытке (как в rollback), на переходе предела —
        # ОДНО hold-уведомление, дальше — тишина (долгий простой на 6 часов
        # не должен стоить 360 уведомлений).
        if fail == AWGS_RELAY_FAIL_LIMIT:
            _notify("awg_relay_hold",
                    f"AWG kernel-relay: relaunch-лестница исчерпана "
                    f"({why}, {iface}) — ОТКАТ ОТКЛЮЧЁН (режим «только "
                    f"уведомлять»): ДЕРЖУ режим, relaunch продолжается "
                    f"каждую минуту; напарник вернётся — флоу оживёт сам")
        elif fail < AWGS_RELAY_FAIL_LIMIT:
            _notify("awg_relay_dir_dead",
                    f"AWG kernel-relay: флоу мёртв ({why}), relaunch НЕ "
                    f"помог (попытка {fail}/{AWGS_RELAY_FAIL_LIMIT}, "
                    f"{iface})")
        _relay_state_update(lambda b: b.update({"fail_count": fail}))
        return f"hold-{fail}"

    _notify("awg_relay_dir_dead",
            f"AWG kernel-relay: флоу мёртв ({why}), relaunch НЕ помог "
            f"(попытка {fail}/{AWGS_RELAY_FAIL_LIMIT}, {iface})")
    if fail >= AWGS_RELAY_FAIL_LIMIT:
        try:
            relay_disable(reason=f"watchdog #{fail}: флоу ({why}) не "
                                 "оживал после relaunch", auto=True)
        except Exception as exc:
            core.log_to_file("WARN", f"relay_disable: {exc}")
        return "rollback"
    _relay_state_update(lambda b: b.update({"fail_count": fail}))
    return f"pending-{fail}"


def _time_sleep_wrapper(sec: float) -> None:
    """Обёртка для тестируемости (мокается в юнит-тестах)."""
    time.sleep(sec)


def relay_watchdog_setup() -> bool:
    """Создаёт и запускает watchdog-таймер (тик каждую минуту).

    Wrapper PYTHONPATH-safe — паттерн awgs_cascade_failover_setup /
    split_watchdog_setup (bare python3 -c из-под systemd падает с
    ModuleNotFoundError).
    """
    from .awg_constants import (AWGS_RELAY_SCRIPT, AWGS_RELAY_SVC,
                                AWGS_RELAY_TIMER)
    core = _core_module()
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

    wrapper = (
        "#!/bin/bash\n"
        "# AWG kernel-relay health-тик (watchdog флоу).\n"
        "mkdir -p /root/awg\n"
        f"export PYTHONPATH=\"{installer_path}:$PYTHONPATH\"\n"
        f"/usr/bin/python3 -c \"\n"
        f"import sys\n"
        f"sys.path.insert(0, '{installer_path}')\n"
        f"from chimera.modules.awg_kernel_relay import relay_health_tick\n"
        f"relay_health_tick()\n"
        f"\" >> /root/awg/awg_standalone.log 2>&1\n"
    )
    AWGS_RELAY_SCRIPT.write_text(wrapper)
    AWGS_RELAY_SCRIPT.chmod(0o755)

    AWGS_RELAY_SVC.write_text(
        "[Unit]\n"
        "Description=AWG kernel-relay health check (awg-kernel-relay-watchdog)\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={AWGS_RELAY_SCRIPT}\n"
    )
    AWGS_RELAY_TIMER.write_text(
        "[Unit]\n"
        "Description=AWG kernel-relay watchdog (health-тик каждую минуту)\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=*:0/1\n"
        "AccuracySec=10s\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    core._run(["systemctl", "enable", "--now",
               "awg-kernel-relay-watchdog.timer"],
              capture=True, check=False)
    r = core._run(["systemctl", "is-active",
                   "awg-kernel-relay-watchdog.timer"],
                  capture=True, check=False)
    return (r.stdout or "").strip() == "active"


def relay_watchdog_teardown() -> bool:
    """Останавливает и удаляет watchdog-таймер/сервис/wrapper."""
    from .awg_constants import (AWGS_RELAY_SCRIPT, AWGS_RELAY_SVC,
                                AWGS_RELAY_TIMER)
    core = _core_module()
    for unit in ("awg-kernel-relay-watchdog.timer",
                 "awg-kernel-relay-watchdog.service"):
        core._run(["systemctl", "stop", unit], check=False, quiet=True)
        core._run(["systemctl", "disable", unit], check=False, quiet=True)
    AWGS_RELAY_TIMER.unlink(missing_ok=True)
    AWGS_RELAY_SVC.unlink(missing_ok=True)
    AWGS_RELAY_SCRIPT.unlink(missing_ok=True)
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    return True


# ────────────────────────────────────────────────────────────────────────────
#  ЧАСТЬ 5. TUI (канон проекта: рамки/боксы/промпты _core)
# ────────────────────────────────────────────────────────────────────────────

def _fmt_bytes(n) -> str:
    """Байты → человекочитаемо (канон _fmt_bytes split-модуля)."""
    n = int(n or 0)
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} МиБ"
    if n >= 1024:
        return f"{n / 1024:.1f} КиБ"
    return f"{n} Б"


def relay_free_port(addr: str = "0.0.0.0") -> int:
    """Свободный UDP-порт (bind:0 → getsockname) — подсказка промптов."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((addr, 0))
        return s.getsockname()[1]


def _relay_status_info() -> dict:
    """Краткие данные статуса для меню (не бросает исключений)."""
    from .awg_constants import AWGS_RELAY_ROOT
    core = _core_module()
    box = relay_state_get()
    out = {
        "box": box,
        "enabled": bool(box.get("enabled")),
        "record": False,
    }
    iface = box.get("iface")
    if iface:
        record = AWGS_RELAY_ROOT / (iface + ".json")
        out["record"] = record.exists()
        try:
            out["probe"] = relay_iface_probe(iface)
        except Exception:
            out["probe"] = {"up": False, "handshake_age": None, "tx": 0, "rx": 0}
    try:
        r = core._run(["systemctl", "is-active",
                       "awg-kernel-relay-watchdog.timer"],
                      capture=True, check=False)
        out["watchdog"] = (r.stdout or "").strip() == "active"
    except Exception:
        out["watchdog"] = False
    return out


def _relay_status_screen() -> None:
    """Бокс статуса kernel-relay (юнит/endpoint/handshake/watchdog)."""
    from .awg_constants import AWGS_RELAY_STALE_SEC
    core = _core_module()
    _box_top, _box_row, _box_bottom = (core._box_top, core._box_row,
                                        core._box_bottom)
    GREEN, RED, DIM, NC = core.GREEN, core.RED, core.DIM, core.NC
    st = _relay_status_info()
    box = st.get("box") or {}
    print()
    _box_top("СТАТУС AWG KERNEL-RELAY")
    _box_row()
    if not box:
        _box_row(f"  {DIM}не настроен{NC}")
        _box_bottom()
        return
    _box_row(f"  Режим: "
             + (f"{GREEN}ВКЛЮЧЁН{NC}" if st.get("enabled") else f"{DIM}выключен{NC}")
             + f"   iface: {box.get('iface', '?')}   "
               f"endpoint: {box.get('endpoint_old', '?')} → "
               f"{box.get('endpoint_target', '?')}")
    ports = box.get("ports") or {}
    _box_row(f"  Флоу: {box.get('addr', '?')}:{ports.get('tx', '?')} → "
             f"{box.get('peer', '?')}:{ports.get('remote_rx', '?')} "
             f"(назад {ports.get('remote_tx', '?')})")
    _box_row(f"  Прелюдия: {box.get('preset', '?')}"
             + (f" (refresh {box.get('refresh')} c)"
                if box.get("refresh") else ""))
    probe = st.get("probe") or {}
    if probe.get("up") and probe.get("handshake_age") is not None:
        age = probe["handshake_age"]
        col = GREEN if age <= AWGS_RELAY_STALE_SEC else RED
        _box_row(f"  Handshake: {col}{age} сек назад{NC}   "
                 f"↑{_fmt_bytes(probe.get('tx'))} "
                 f"↓{_fmt_bytes(probe.get('rx'))}")
    else:
        _box_row(f"  Handshake: {RED}нет (флоу мёртв или iface не поднят){NC}")
    _box_row(f"  Запись /run: "
             + (f"{GREEN}есть{NC}" if st.get("record") else f"{RED}нет{NC}"))
    _box_row(f"  Watchdog: "
             + (f"{GREEN}active{NC}" if st.get("watchdog") else f"{DIM}off{NC}"))
    _box_row(f"  Откат watchdog: "
             + ("уведомить + авто-откат" if _fail_action_norm(
                   box.get("fail_action")) == "rollback"
               else f"{GREEN}ТОЛЬКО уведомить (без отката){NC}"))
    if box.get("fail_count"):
        _box_row(f"  Неудач watchdog: {RED}{box['fail_count']}{NC}")
    _box_bottom()


def _relay_plan_box(cfg: dict) -> None:
    """Бокс-план для НАПАРНИКА (порт-матчинг двухшаговой установки)."""
    core = _core_module()
    _box_top, _box_row, _box_bottom = (core._box_top, core._box_row,
                                       core._box_bottom)
    GREEN, DIM, NC = core.GREEN, core.DIM, core.NC
    print()
    _box_top("ПЛАН ДЛЯ НАПАРНИКА — ввести там пункт 1")
    _box_row()
    _box_row(f"  {DIM}На напарнике (B) ввести:{NC}")
    _box_row(f"  {GREEN}iface:{NC}            свой awg-линк (обычно awg1)")
    _box_row(f"  {GREEN}addr:{NC}             свой внешний IPv4")
    _box_row(f"  {GREEN}loop:{NC}             любой свободный UDP-порт")
    _box_row(f"  {GREEN}tx / rx:{NC}         свободный / 443-подобный")
    _box_row(f"  {GREEN}remote_tx:{NC}        {cfg['remote_tx']}  ← ваш tx")
    _box_row(f"  {GREEN}remote_rx:{NC}        {cfg['remote_rx']}  ← ваш rx")
    _box_row(f"  {GREEN}Прелюдия:{NC}         тот же пресет "
             f"«{cfg.get('preset', 'dns-fixed')}»")
    _box_row(f"  {DIM}Watchdog-откат: выбрать тот же режим при включении "
             f"на напарнике (п.1 спросит){NC}")
    _box_row()
    _box_row(f"  {DIM}Напарник будет слать:{NC}")
    _box_row(f"  {GREEN}его tx → ваш rx:{NC}   {cfg['remote_tx']} → "
             f"{cfg['addr']}:{cfg['rx']}")
    _box_row(f"  {DIM}ВАЖНО: между включением на A и B — окно простоя")
    _box_row(f"  {DIM}в секунды. Запускайте оба конца подряд.")
    _box_bottom()
    print()


def _relay_prelude_ask(box: dict) -> dict:
    """Промпты пресета прелюдии (+domain/hex) — возвращает настройки."""
    core = _core_module()
    _box_top, _box_row, _box_item, _box_desc, _box_bottom = (
        core._box_top, core._box_row, core._box_item, core._box_desc,
        core._box_bottom)
    CYAN, GREEN, DIM, NC = core.CYAN, core.GREEN, core.DIM, core.NC
    cur = box.get("preset", "dns-fixed")
    print()
    _box_top("ПРЕЛЮДИЯ ФЛОУ • первая датаграмма (DPI решает по ней)")
    _box_row()
    _box_desc("DPI классифицирует флоу по первому пакету. DNS-запрос —")
    _box_desc("белый список; WG-трафик едет по вайллистнутому флоу.")
    _box_row()
    for key, entry in [
        ("1", ("dns-fixed", "DNS example.com, фикс-txid (боевой пилот)")),
        ("2", ("dns-rand", "DNS example.com, случайный txid")),
        ("3", ("custom-domain", "DNS своего домена")),
        ("4", ("custom-hex", "Raw hex (свои байты)")),
        ("5", ("none", "Без прелюдии (чистый релей)")),
        ("Q", ("", "оставить текущий")),
    ]:
        mark = f" {GREEN}[текущий: {cur}]{NC}" if entry[0] == cur else ""
        _box_item(key, entry[1] + mark)
    _box_bottom()
    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ch = ""
    preset = {"1": "dns-fixed", "2": "dns-rand", "3": "custom-domain",
              "4": "custom-hex", "5": "none"}.get(ch, "")
    domain, hex_data = "", ""
    if preset == "custom-domain":
        domain = core._box_ask("Домен для DNS-запроса (например, ya.ru)")
        if not domain:
            preset = ""
    elif preset == "custom-hex":
        hex_data = core._box_ask("Hex-датаграмма (пробелы игнорируются)")
        if not hex_data:
            preset = ""
    refresh = core._box_ask("Refresh-интервал пере-сева флоу, сек "
                            "(0 = выкл)", str(box.get("refresh", 0)))
    try:
        refresh = int(refresh or 0)
    except ValueError:
        refresh = 0
    return {"preset": preset, "domain": domain, "hex_data": hex_data,
            "refresh": refresh}


def _relay_fail_action_ask(box: dict) -> str:
    """Промпт поведения watchdog при исчерпании relaunch-лестницы.

    Фичареквест Виталия (26.11): «уведомлять, но не откатывать на прямой
    эндпоинт. Смысл: я и так знаю, что прямой не заработает, но в случае
    отключения или долгой перезагрузки одного из узлов потом ещё и режим
    работы восстанавливать надо будет». Возвращает «rollback» либо
    «notify_only»; умолчание — текущее из state (дальше «rollback»);
    Q/мусор — текущий без изменений.
    """
    core = _core_module()
    _box_top, _box_row, _box_item, _box_desc, _box_bottom = (
        core._box_top, core._box_row, core._box_item, core._box_desc,
        core._box_bottom)
    CYAN, GREEN, DIM, NC = core.CYAN, core.GREEN, core.DIM, core.NC
    cur = _fail_action_norm(box.get("fail_action"))
    print()
    _box_top("WATCHDOG • ПОВЕДЕНИЕ ПРИ ИСЧЕРПАНИИ ЛЕСТНИЦЫ")
    _box_row()
    _box_desc("3 неудачи relaunch подряд (флоу мёртв, юнит поднимался) —")
    _box_desc("дальше два честных поведения:")
    _box_row()
    for key, entry in [
        ("1", ("rollback", "Уведомить + АВТО-ОТКАТ на прямой endpoint "
                            "(по умолчанию)")),
        ("2", ("notify_only", "ТОЛЬКО уведомить, БЕЗ отката — держать "
                              "режим, relaunch продолжается каждую минуту")),
        ("Q", ("", "оставить текущий")),
    ]:
        mark = f" {GREEN}[текущий: {cur}]{NC}" if entry[0] == cur else ""
        _box_item(key, entry[1] + mark)
    _box_row()
    _box_desc("«Только уведомлять» — для кейсов, где прямой endpoint всё")
    _box_desc("равно мёртв (двусторонний кат): откат снял бы режим, и после")
    _box_desc("ребута/долгого простоя напарника восстанавливать руками.")
    _box_desc("Напарник вернётся — флоу оживёт сам, TG сообщит.")
    _box_bottom()
    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ch = ""
    return {"1": "rollback", "2": "notify_only"}.get(ch, cur)


def _relay_enable_interactive() -> None:
    """Промпты включения релея на ЭТОЙ ноде (полная кастомизация)."""
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success
    _box_top, _box_row, _box_kv, _box_bottom = (core._box_top, core._box_row,
                                                core._box_kv, core._box_bottom)
    CYAN, GREEN, DIM, NC = core.CYAN, core.GREEN, core.DIM, core.NC

    box = relay_state_get()
    if relay_is_on():
        warn("Релей уже включён на этой ноде — сначала выключите (п.3)")
        return

    print()
    _box_top("ВКЛЮЧЕНИЕ AWG KERNEL-RELAY • ЭТА НОДА")
    _box_row()
    _box_row(f"  {DIM}Нужен живой kernel AWG с ровно ОДНИМ пиром и прямым{NC}")
    _box_row(f"  {DIM}IPv4 endpoint'ом (обычно — awg1 каскадного линка).{NC}")
    _box_row(f"  {DIM}Ставится на ОБЕИХ нодах линка; между включениями —{NC}")
    _box_row(f"  {DIM}окно простоя в секунды (запускайте оба конца подряд).{NC}")
    _box_row()
    _box_kv("iface", "awg-линк (обычно awg1)")
    _box_kv("addr", "ваш внешний IPv4 (источник флоу)")
    _box_kv("loop", "свободный UDP-порт на localhost")
    _box_kv("tx / rx", "ваши wire-порты (rx: 443 «QUIC-вид» / 53 «DNS»)")
    _box_kv("remote_tx/rx", "wire-порты НАПАРНИКА (из его плана)")
    _box_kv("Прелюдия", "пресет ниже (боевой — DNS example.com)")
    _box_bottom()

    iface = core._box_ask("iface (awg-линк)", "awg1")
    if not _iface_name_valid(iface):
        warn(f"Ожидается имя awgN, получено {iface!r}")
        return

    try:
        ident, old = snapshot(iface)
    except (ValueError, KeyError, subprocess.SubprocessError) as exc:
        warn(f"Снимок не удался: {exc} — нужен kernel AWG с одним пиром "
             "и прямым IPv4 endpoint")
        return
    host, sep, number = old.rpartition(":")
    if not sep:
        warn(f"Endpoint {old!r} не host:port — нужен прямой IPv4")
        return

    # Подсказка адреса: src маршрута до пира
    addr_default = ""
    try:
        route = json.loads(run("ip", "-j", "route", "get", host))
        addr_default = route[0].get("src", "") or ""
    except Exception:
        addr_default = ""
    addr = core._box_ask("Ваш внешний IPv4 (источник флоу)", addr_default)
    if not addr:
        warn("Адрес обязателен")
        return

    loop_d = str(relay_free_port("127.0.0.1"))
    loop = core._box_ask("loop UDP-порт (localhost)", loop_d)
    tx = core._box_ask("tx UDP-порт (ваш исходящий; случайный = клиентский вид)",
                       str(relay_free_port(addr)))
    rx = core._box_ask("rx UDP-порт (ваш входящий; 443 «QUIC-вид», 53 «DNS»)",
                        "443")
    remote_rx = core._box_ask("remote_rx — rx-порт НАПАРНИКА", "443")
    remote_tx = core._box_ask("remote_tx — tx-порт НАПАРНИКА",
                              str(relay_free_port("0.0.0.0")))

    prelude_cfg = _relay_prelude_ask(box)
    preset = prelude_cfg.get("preset") or box.get("preset", "dns-fixed")
    refresh = prelude_cfg.get("refresh", 0)

    try:
        relay_prelude_build(preset, prelude_cfg.get("domain", ""),
                             prelude_cfg.get("hex_data", ""))
    except ValueError as exc:
        warn(f"Прелюдия: {exc}")
        return

    fail_action = _relay_fail_action_ask(box)

    confirm = core._box_ask(
        f"Включить релей: {iface} {old} → 127.0.0.1:{loop} "
        f"(tx {addr}:{tx} → {host}:{remote_rx})? [y/N]", "").lower()
    if confirm not in ("y", "yes", "д", "да"):
        info("Отменено")
        return

    cfg = dict(iface=iface, addr=addr, loop=loop, tx=tx, rx=rx,
               remote_tx=remote_tx, remote_rx=remote_rx,
               preset=preset, domain=prelude_cfg.get("domain", ""),
               hex_data=prelude_cfg.get("hex_data", ""),
               refresh=refresh,
               restore_on_boot=bool(box.get("restore_on_boot")),
               fail_action=fail_action)
    ok, reason = relay_enable(cfg)
    if not ok:
        warn(f"Не удалось: {reason}")
        return
    success("Kernel-relay включён: туннель и ключи НЕ менялись — "
            "endpoint уехал на localhost-релей, оба wire-флоу с "
            "DNS-прелеюдией")
    cfg.update({"addr": addr, "rx": rx, "tx": tx,
                "remote_tx": remote_tx, "remote_rx": remote_rx,
                "preset": preset})
    _relay_plan_box(cfg)


def _relay_diagnose() -> None:
    """Диагностика: журнал юнита (EPERM), снимок AWG, план портов."""
    core = _core_module()
    info = core.info
    box = relay_state_get()
    unit = box.get("unit", "")
    iface = box.get("iface", "")
    print()
    if unit:
        info(f"journalctl -u {unit} (последние 25 строк — EPERM живёт тут):")
        p = core._run(["journalctl", "-u", unit, "--no-pager", "-n", "25"],
                      capture=True, check=False)
        print(p.stdout if hasattr(p, "stdout") else p)
    if iface:
        try:
            info(f"awg show {iface}:")
            p = core._run(["awg", "show", iface], capture=True, check=False)
            print(p.stdout if hasattr(p, "stdout") else p)
            info(f"endpoint: {snapshot(iface)[1]}")
        except Exception as exc:
            core.warn(f"Снимок не удался: {exc}")
    print()


def do_manage_awg_kernel_relay() -> None:
    """TUI-меню kernel-relay (вызывается из меню каскада, п.9)."""
    core = _core_module()
    _box_top, _box_row, _box_bottom = (core._box_top, core._box_row,
                                        core._box_bottom)
    _box_item, _box_desc = core._box_item, core._box_desc
    info, warn, success = core.info, core.warn, core.success
    CYAN, NC, GREEN, DIM = core.CYAN, core.NC, core.GREEN, core.DIM

    while True:
        import os
        os.system("clear")
        print()
        state_box = relay_state_get()
        on = bool(state_box.get("enabled"))

        _box_top("AWG-релей • один туннель + UDP-релей (обход 16к)")
        _box_row()
        _box_desc("kernel awg1 ─► 127.0.0.1:loop ─► релей ─► DNS-флоу ─►")
        _box_desc("релей напарника ─► 127.0.0.1:loop ─► kernel awg1")
        _box_desc("Кейс Виталия: двусторонний кат 16к режет даже handshake'ы")
        _box_desc("ДВУХ туннелей (split-direction бессилен — нет встречного")
        _box_desc("обмена для ключей). Релей НЕ добавляет второй туннель:")
        _box_desc("меняется только проводной транспорт endpoint'а.")
        _box_row()
        if state_box:
            ports = state_box.get("ports") or {}
            _box_row(f"  Режим: "
                     + (f"{GREEN}ВКЛЮЧЁН{NC}" if on else f"{DIM}выключен{NC}")
                     + f"  iface: {state_box.get('iface', '?')}  "
                       f"{state_box.get('endpoint_old', '?')} → "
                       f"{state_box.get('endpoint_target', '?')}")
            _box_row(f"  Флоу: {state_box.get('addr', '?')}:"
                     f"{ports.get('tx', '?')} → {state_box.get('peer', '?')}:"
                     f"{ports.get('remote_rx', '?')}  прелюдия: "
                     f"{state_box.get('preset', '?')}"
                     + (f" (refresh {state_box.get('refresh')} c)"
                        if state_box.get("refresh") else ""))
            _box_row("  Watchdog-откат: "
                     + ("уведомить + авто-откат"
                        if _fail_action_norm(
                            state_box.get("fail_action")) == "rollback"
                        else f"{GREEN}ТОЛЬКО уведомить (без отката){NC}"))
        else:
            _box_row(f"  {DIM}Релей не настроен на этой ноде{NC}")
        _box_row()
        _box_item("1", "Включить на ЭТОЙ ноде (iface → порты → прелюдия)")
        _box_desc("Двухшаговая установка: включить здесь, напечатанный план "
                  "ввести на напарнике. Окно простоя — секунды.")
        _box_item("2", "Статус: юнит / endpoint / handshake / watchdog")
        _box_item("3", "Выключить и восстановить прямой endpoint (guarded)")
        _box_item("4", "Прелюдия: пресет / домен / hex / refresh-интервал")
        _box_item("5", "Watchdog: включить/выключить (health-тик в минуту)")
        _box_item("6", "Автовосстановление после ребута: вкл/выкл")
        _box_item("7", "Watchdog-откат: уведомить+откат / ТОЛЬКО уведомить")
        _box_desc("Поведение при исчерпании relaunch-лестницы (3 неудачи): "
                  "откат")
        _box_desc("на прямой endpoint либо удержание режима — фичареквест "
                  "кейса")
        _box_item("8", "Диагностика: journalctl юнита + awg show")
        _box_item("Q", "Назад")
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch == "1":
            _relay_enable_interactive()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            _relay_status_screen()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            if not relay_is_on():
                warn("Релей не включён на этой ноде")
            else:
                ok = input("\n  Выключить релей и восстановить прямой "
                           "endpoint? [y/N]: ").strip().lower()
                if ok in ("y", "yes", "д", "да"):
                    try:
                        relay_disable(reason="выключен вручную")
                        success("Релей выключен: прямой endpoint "
                                "восстановлен (guarded-сверкой)")
                    except (ValueError, subprocess.SubprocessError) as exc:
                        warn(f"Откат не прошёл guarded-сверку: {exc} "
                             "(запись сохранена для разбора)")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            box = relay_state_get()
            prelude_cfg = _relay_prelude_ask(box)
            preset = prelude_cfg.get("preset") or box.get("preset",
                                                          "dns-fixed")
            if not prelude_cfg.get("preset"):
                info("Пресет не менялся")
            try:
                relay_prelude_build(preset, prelude_cfg.get("domain", ""),
                                    prelude_cfg.get("hex_data", ""))
            except ValueError as exc:
                warn(f"Прелюдия: {exc}")
                input(f"{core.BLUE}Нажмите Enter...{NC}")
                continue
            if relay_is_on():
                info("Вступит в силу при следующем включении "
                     "(выкл → вкл; живой флоу не пересеиваем)")
            _relay_state_update(lambda b: b.update({
                "preset": preset,
                "prelude_domain": prelude_cfg.get("domain", ""),
                "prelude_hex_data": prelude_cfg.get("hex_data", ""),
                "refresh": prelude_cfg.get("refresh", 0),
            }))
            success(f"Прелюдия: пресет «{preset}» записан в state")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            if relay_watchdog_setup():
                success("Watchdog включён (таймер каждую минуту)")
            else:
                warn("Не удалось включить watchdog (см. лог)")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            cur = bool(relay_state_get().get("restore_on_boot"))
            _new = not cur
            _mode = ("ВКЛЮЧИТЬ автовосстановление после ребута "
                     "(watchdog поднимет релей из state)"
                     if _new else
                     "ВЫКЛЮЧИТЬ автовосстановление (после ребута режим "
                     "снимется с уведомлением)")
            ok = input(f"\n  {_mode}? [y/N]: ").strip().lower()
            if ok in ("y", "yes", "д", "да"):
                if _relay_state_update(lambda b: b.update(
                        {"restore_on_boot": _new})):
                    success("Автовосстановление: " + ("вкл" if _new else "выкл"))
                else:
                    warn("State НЕ сохранён (см. лог)")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "7":
            box = relay_state_get()
            cur = _fail_action_norm(box.get("fail_action"))
            new = _relay_fail_action_ask(box)
            if new == cur:
                info("Режим watchdog-отката не менялся")
            elif _relay_state_update(lambda b: b.update(
                    {"fail_action": new})):
                success("Watchdog-откат: "
                        + ("уведомить + авто-откат" if new == "rollback"
                           else "ТОЛЬКО уведомить (без отката)")
                                                + " — вступает в силу со следующего тика (минута)")
            else:
                warn("State НЕ сохранён (см. лог)")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "8":
            _relay_diagnose()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", ""):
            break


if __name__ == "__main__":
    worker(json.loads(sys.argv[1]))
