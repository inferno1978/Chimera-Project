#!/usr/bin/env python3
"""
chimera/modules/warp_telegram_probe.py
───────────────────────────────────────────────────────────────────────────────
MTProto-проба Telegram-датацентров через WARP — проверка «через этот
WARP-выход Telegram реально работает?».

Порт telegram.go из niklzz/warpscout-tg (форк vernette/warpscout, MIT).
Идея форка: простое TCP-соединение к ДЦ Telegram ничего не доказывает —
DPI-система может завершить хендшейк в сторону Telegram и молча съесть
данные. ДЦ засчитывается только когда реально ответил на НАСТОЯЩИЙ
MTProto-запрос (req_pq_multi, plaintext). Ответить должны все пять ДЦ:
аккаунт Telegram живёт на одном ДЦ и клиент не может выбрать другой, так
что выход, с которого отвечают лишь три из пяти, для части аккаунтов
мёртв (живой пример из warpscout-tg: WARP-выход во Франкфурте — DC1/3/5
отвечали, DC2/4 нет, Telegram Desktop висел в «connecting...»).

Механика
────────
  1. Пять адресов ДЦ — хардкод IPv4 (как у клиента Telegram: клиент
     дозванивается напрямую, резолв имён тестирует путь, которого
     Telegram никогда не использует).
  2. probe_dc(): TCP-connect + отправка req_pq_multi (intermediate
     transport 0xEEEEEEEE, auth_key_id=0, msg_id=unix<<32, длина 20,
     конструктор 0xBE7E8EF1, nonce 16 случайных байт — итого 48 байт) и
     чтение 4-байтового заголовка ответа. res_pq ~84 байт, поэтому всё,
     что вне разумного диапазона длин, — не Telegram.
  3. probe_all_dcs(): все 5 ДЦ параллельно под общим дедлайном (ходьба
     по очереди стоила бы 5 x timeout на блокированном выходе). RTT
     результата = время до ответа; итог = маска достигнутых ДЦ, «все 5»
     обязательно.
  4. Маршрутизация пробы через wg-warp: если WARP в FULL — пакеты и так
     идут через туннель; если включён telemt_warp_route — fwmark уже
     заворачивает ДЦ в туннель; в остальных случаях модуль СТАВИТ
     ВРЕМЕННЫЕ ip rule to <dc> lookup + таблицу default dev wg-warp
     (приоритет ниже telemt-правила, поэтому чужую маршрутизацию не
     перебивает даже при пересечении) и снимает их сразу после пробы.

Автономность
────────────
Модуль зависит только от chimera.modules.warp.WG_INTERFACE (как
telemt_warp_route) и системных бинарей ip(8)/curl. warp.py и
telemt_warp_route.py импортируют этот модуль ЛЕНИВО (внутри функций) —
обратный верхнеуровневый импорт создаёт цикл, т.к. модуль импортирует
warp.

Точки входа:
    from chimera.modules.warp_telegram_probe import (
        probe_all_dcs, telegram_status_str)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import random
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# warp.py лежит рядом — относительный импорт пакета при любом запуске.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.warp import WG_INTERFACE as _WARP_IFACE

# ── Константы ─────────────────────────────────────────────────────────────
# Адреса MTProto-ДЦ Telegram (IPv4). Хардкод намеренный — см. докстринг.
# Порядок = бит в маске (бит i = TELEGRAM_DCS[i]).
TELEGRAM_DCS: tuple[tuple[str, str], ...] = (
    ("DC1", "149.154.175.50"),
    ("DC2", "149.154.167.51"),
    ("DC3", "149.154.175.100"),
    ("DC4", "149.154.167.91"),
    ("DC5", "91.108.56.130"),
)
TG_DC_PORT = 443

# req_pq_multi — конструктор MTProto (plaintext, unencrypted).
MTPROTO_REQ_PQ_MULTI = 0xBE7E8EF1
# intermediate transport magic (4 x 0xEE).
MTPROTO_INTERMEDIATE = b"\xee\xee\xee\xee"
# Ответ res_pq ~84 байта: рамка длиннее 64КиБ — не Telegram.
FRAME_LEN_MAX = 1 << 16

# Общий дедлайн на все 5 ДЦ параллельно (один таймаут на весь выход,
# а не на каждый ДЦ по очереди — паттерн reachedDCs из warpscout-tg).
TG_PROBE_TIMEOUT = 6.0  # сек

# Временная таблица/приоритет для проб, когда ДЦ ещё не идёт через wg-warp.
# 302 не пересекается с telemt_warp_route (300) и youtube_warp_route (301).
# Приоритет 155 — ПОСЛЕ telemt-правила fwmark (150): при включённом
# telemt_warp_route mangle уже заворачивает пакеты по приоритету 150, и
# наши правила просто не срабатывают; при выключенном — подхватывают ДЦ.
PROBE_TABLE = 302
PROBE_RULE_PRIORITY = 155


# ── Сборка MTProto-запроса (порт mtprotoProbe из telegram.go) ────────────
def build_req_pq_multi(unix_ts: int | None = None, nonce: bytes | None = None) -> bytes:
    """Пакет req_pq_multi в intermediate-транспорте, 48 байт.

    Структура (байт-в-байт из warpscout-tg telegram.go):
      0xEEEEEEEЕ (4) — magic intermediate transport;
      LE32(40)      — длина кадра: auth_key_id + msg_id + len + req_pq_multi;
      8 нулей       — auth_key_id = 0 (plaintext-сообщение);
      LE64(unix<<32)— msg_id (младшие 32 бита нулевые, msg_id % 4 == 0,
                      как требуют клиенты);
      LE32(20)      — message_data_length;
      LE32(0xBE7E8EF1) — конструктор req_pq_multi;
      16 байт       — nonce (случайный).
    """
    if unix_ts is None:
        unix_ts = int(time.time())
    if nonce is None:
        nonce = random.Random().randbytes(16) if hasattr(random.Random, "randbytes") \
            else bytes(random.randint(0, 255) for _ in range(16))
    if len(nonce) != 16:
        raise ValueError(f"nonce должен быть 16 байт, получено {len(nonce)}")
    msg_id = (unix_ts << 32) & 0xFFFFFFFFFFFFFFFF
    return (
        MTPROTO_INTERMEDIATE
        + struct.pack("<I", 40)
        + b"\x00" * 8
        + struct.pack("<Q", msg_id)
        + struct.pack("<I", 20)
        + struct.pack("<I", MTPROTO_REQ_PQ_MULTI)
        + nonce
    )


def _frame_header_plausible(sock: socket.socket) -> bool:
    """Читает 4-байтовый заголовок ответа. Валидной считается длина кадра
    0 < n <= 64КиБ — res_pq ~84 байта; всё иное — не Telegram."""
    try:
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return False
            hdr += chunk
    except (OSError, socket.timeout):
        return False
    (n,) = struct.unpack("<I", hdr)
    return 0 < n <= FRAME_LEN_MAX


# ── Маршрутизация пробы через wg-warp ────────────────────────────────────
def _ip_run(args: list) -> subprocess.CompletedProcess:
    """ip(8) без исключений: в тестах патчится, в бою молчит в stdout."""
    return subprocess.run(args, capture_output=True, text=True, timeout=8)


def _dc_goes_through_warp(dc_ip: str) -> bool:
    """`ip route get <dc>` показывает фактический интерфейс для ДЦ.
    dev wg-warp → маршрутизация уже есть (FULL/SELECTIVE с ДЦ в списках).
    dev eth0 → возможно, пакет всё равно уйдёт в туннель по fwmark
    (telemt_warp_route) — но временное правило с приоритетом НИЖЕ fwmark
    в этом случае просто не сработает, ставить безопасно."""
    r = _ip_run(["ip", "route", "get", dc_ip])
    return "dev wg-warp" in (r.stdout or "")


def _warp_iface_up() -> bool:
    r = _ip_run(["ip", "link", "show", _WARP_IFACE])
    return r.returncode == 0


def _ensure_probe_routing() -> tuple[bool, list]:
    """Гарантирует, что пробы ДЦ пойдут через wg-warp.

    Возвращает (ok, cleanup): ok=False — интерфейс wg-warp не поднят
    (проба бессмысленна); cleanup — список команд отката (уже НЕ выполненных,
    если ok=False). Вызывать cleanup в finally вызывающего кода.

    Идемпотентно и неинвазивно: правило максимально специфично (to <ip>),
    приоритет ниже telemt-fwmark, снятие — сразу после пробы.
    """
    if not _warp_iface_up():
        return False, []
    need = [ip for (_name, ip) in TELEGRAM_DCS if not _dc_goes_through_warp(ip)]
    if not need:
        # Всё уже завёрнуто в туннель (FULL / SELECTIVE с ДЦ / телемт).
        return True, []
    # Таблица default dev wg-warp + по правилу to <ip> на каждый ДЦ.
    _ip_run(["ip", "route", "replace", "default", "dev", _WARP_IFACE,
             "table", str(PROBE_TABLE)])
    rules: list[str] = []
    for ip in need:
        rules.append(ip)
        _ip_run(["ip", "rule", "add", "to", ip, "lookup", str(PROBE_TABLE),
                 "priority", str(PROBE_RULE_PRIORITY)])
    # cleanup удаляет правила и таблицу.
    cleanup: list = [
        ["ip", "rule", "del", "to", ip, "lookup", str(PROBE_TABLE),
         "priority", str(PROBE_RULE_PRIORITY)] for ip in rules
    ] + [["ip", "route", "del", "default", "dev", _WARP_IFACE,
          "table", str(PROBE_TABLE)]]
    return True, cleanup


def _run_cleanup(cleanup: list) -> None:
    for args in cleanup:
        _ip_run(args)


# ── Проба одного ДЦ ──────────────────────────────────────────────────────
def probe_dc(dc_ip: str, port: int = TG_DC_PORT, timeout: float = 4.0) -> tuple[bool, float | None]:
    """TCP-connect + req_pq_multi + чтение заголовка ответа.
    Возвращает (answered, rtt_ms). ДЦ засчитан только по реальному
    MTProto-ответу — TCP-connect сам по себе ничего не доказывает."""
    start = time.perf_counter()
    try:
        with socket.create_connection((dc_ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(build_req_pq_multi())
            if not _frame_header_plausible(sock):
                return False, None
        return True, (time.perf_counter() - start) * 1000.0
    except OSError:
        return False, None


# ── Проба всех ДЦ (порт reachedDCs из telegram.go) ───────────────────────
def probe_all_dcs(timeout: float = TG_PROBE_TIMEOUT) -> dict:
    """Все 5 ДЦ параллельно под одним дедлайном. Ответ — словарь:
      ok            — ответили ВСЕ ДЦ (главное условие warpscout-tg);
      reached_mask  — бит i = TELEGRAM_DCS[i] ответил;
      reached_names — список ответивших («DC1, DC2, …»);
      missing_names — не ответившие (для вывода);
      worst_rtt_ms  — RTT самого медленного ответившего (аккаунт юзера
                      может жить именно на нём) или None;
      routed_via_warp — ставились ли временные правила (инфо для лога);
      warp_up       — был ли поднят wg-warp на момент пробы.
    При не поднятом wg-warp возвращает warp_up=False и ok=False —
    вызывающий код показывает «WARP не поднят», а не «Telegram blocked».
    """
    result: dict = {
        "ok": False, "reached_mask": 0, "reached_names": [],
        "missing_names": [n for (n, _ip) in TELEGRAM_DCS],
        "worst_rtt_ms": None, "routed_via_warp": False, "warp_up": False,
    }
    ok, cleanup = _ensure_probe_routing()
    if cleanup:
        result["routed_via_warp"] = True
    try:
        if not ok:
            return result
        result["warp_up"] = True
        with ThreadPoolExecutor(max_workers=len(TELEGRAM_DCS)) as pool:
            futures = {
                pool.submit(probe_dc, ip, TG_DC_PORT, timeout): (i, name)
                for i, (name, ip) in enumerate(TELEGRAM_DCS)
            }
            for future, (i, name) in futures.items():
                try:
                    answered, rtt = future.result()
                except Exception:
                    # Робастность: проба ДЦ — диагностика, не повод ронять
                    # вызывавший флоу (apply Endpoint / watchdog телемта).
                    answered, rtt = False, None
                if answered:
                    result["reached_mask"] |= 1 << i
                    result["reached_names"].append(name)
                    if rtt is not None:
                        if result["worst_rtt_ms"] is None or rtt > result["worst_rtt_ms"]:
                            result["worst_rtt_ms"] = rtt
    finally:
        if cleanup:
            _run_cleanup(cleanup)

    result["reached_names"] = [n for n, _ in TELEGRAM_DCS if n in result["reached_names"]]
    result["missing_names"] = [n for n, _ in TELEGRAM_DCS if n not in result["reached_names"]]
    result["ok"] = result["reached_mask"] == (1 << len(TELEGRAM_DCS)) - 1
    if result["worst_rtt_ms"] is not None:
        result["worst_rtt_ms"] = round(result["worst_rtt_ms"], 1)
    return result


def telegram_status_str(res: dict) -> str:
    """Человекочитаемая строка статуса: «Telegram: 5/5 · худший 84 мс» /
    «Telegram: 3/5 (нет DC2, DC4)» / «Telegram: blocked» /
    «WARP не поднят — проба Telegram пропущена»."""
    if not res.get("warp_up"):
        return "WARP не поднят — проба Telegram пропущена"
    total = len(TELEGRAM_DCS)
    if res.get("ok"):
        worst = res.get("worst_rtt_ms")
        worst_str = f" · худший {worst:.0f} мс" if worst is not None else ""
        return f"Telegram: {total}/{total}{worst_str}"
    reached = len(res.get("reached_names", []))
    if reached == 0:
        return "Telegram: blocked (не ответил ни один ДЦ)"
    missing = ", ".join(res.get("missing_names", []))
    return f"Telegram: {reached}/{total} (нет {missing})"
