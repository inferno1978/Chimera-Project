"""
chimera/modules/awg_link_probe.py
───────────────────────────────────────────────────────────────────────────────
Зонд плеча entry→exit AWG-каскада + классификатор паттернов среды.

«Универсальность — не универсальный пресет, а универсальный ПРОЦЕСС:
зонд → классификация → генерация → верификация → переопрос» (анализ
кейса «Виталий»: AWG между двумя своими VPS при блокировке 16k — туннель
жил только в одну сторону, «отправить можем, принять нет»; руками собрал
два однонаправленных туннеля). Этот модуль — первые две ступени
процесса: измерить поле и назвать паттерн. Применение — модуль
awg_split_direction (штатная реализация двухтуннельной схемы).

Лестница зондов (по нарастанию стоимости, всё — БЕЗ переключения
пользовательского трафика):
  L0  awg show awg1      — handshake age + transfer sent/recv штатного
                           туннеля каскада (живое плечо под руками);
  L1  ping шлюза exit    — ICMP через awg1 (ядро exit отвечает);
  L2  большой ping       — ping -m <cascade-fwmark> -s 1200 -c 48
                           <probe_host>: поток ~57 КБ В ОБЕ СТОРОНЫ
                           штатным fwmark-путём транзита (table 2000 →
                           awg1 → exit → интернет). Заведомо за порогом
                           антитуннеля 16–32 КБ (FAQ RU_NODE_CASCADE
                           §3.2): живой поток доживает до конца, режущий
                           по объёму — сыплет потерями на середине.

Классификатор сопоставляет показания паттерну среды:

  bidirectional-ok  оба направления живы, большой поток проходит
  one-way-out       sent > 0, recv = 0 — «отправить можем, принять нет»
                    (кейс Виталия) → split-direction
  one-way-in        sent = 0, recv > 0 — обратная редкость
  stream-cut        handshake жив, но большой поток режется (антитуннель
                    16–32 КБ) → канон §9.1–9.2: перенос exit
  udp-dead          handshake нет вовсе — плечо мертво целиком
  flaky             потери в серой зоне (20–80%) — деградация
  no-tunnel         каскад не поднят — зонды не имеют предмета

Матрица LINK_PATTERNS — «симптом → вердикт → рекомендация» — единая
точка правды для TUI-отчёта и тестов. Рекомендации ссылаются на пункты
меню и параграфы FAQ, а не на интуицию пользователя: выбор пресета
вслепую — это ровно опыт «долго бился», модуль выбирает по измерениям.

Все чистые функции (парсер, классификатор, матрица) тестируются без
сервера; живые зонды идут через core._run (mock в тестах).
"""
from __future__ import annotations

import re
from typing import Optional

from .awg_constants import (
    AWGS_AWG1_CONF,
    AWGS_CASCADE_FWMARK,
    AWGS_PROBE_CUT_LOSS_PCT,
    AWGS_PROBE_HOST,
    AWGS_PROBE_OK_LOSS_PCT,
    AWGS_PROBE_PING_COUNT,
    AWGS_PROBE_PING_SIZE,
)
from .awg_state import awgs_state_load


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  ЧИСТЫЕ ФУНКЦИИ: парсеры
# ============================================================================

def link_parse_awg_show(text: str) -> dict:
    """Парсит вывод `awg show <iface>` → показания туннеля.

    Возвращает {handshake_age: int|None, tx: int, rx: int}.
    handshake_age — секунды с последнего handshake (None = не было);
    tx/rx — transfer байт туда/обратно (0 если строки нет).
    Чистая функция (тестируется без сервера).
    """
    out = {"handshake_age": None, "tx": 0, "rx": 0}

    m = re.search(r"latest handshake:\s*(.+?)\s+ago", text or "")
    if m:
        total, found = 0, False
        for part in m.group(1).split(","):
            pm = re.match(r"(\d+)\s+(second|minute|hour|day|week)s?",
                          part.strip())
            if pm:
                found = True
                mult = {"second": 1, "minute": 60, "hour": 3600,
                        "day": 86400, "week": 604800}[pm.group(2)]
                total += int(pm.group(1)) * mult
        if found:
            out["handshake_age"] = total

    m = re.search(r"transfer:\s*([\d.]+)\s*(\w*)\s+received,"
                  r"\s*([\d.]+)\s*(\w*)\s+sent", text or "")
    if m:
        out["rx"] = _parse_size(m.group(1), m.group(2))
        out["tx"] = _parse_size(m.group(3), m.group(4))
    return out


_SIZE_MULT = {"B": 1, "KiB": 1024, "KB": 1000, "MiB": 1024 ** 2,
              "MB": 1000 ** 2, "GiB": 1024 ** 3, "GB": 1000 ** 3,
              "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}


def _parse_size(num: str, unit: str) -> int:
    """«57.6 KiB» → байты (инт, округление вниз — зондам хватает)."""
    try:
        return int(float(num.strip()) * _SIZE_MULT.get(unit.strip(), 1))
    except (ValueError, AttributeError):
        return 0


def link_parse_ping_loss(text: str) -> Optional[int]:
    """Парсит вывод ping → процент потерь или None (нет summary).

    «5 packets transmitted, 3 received, 40% packet loss» → 40.
    Чистая функция.
    """
    m = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", text or "")
    return int(float(m.group(1))) if m else None


# ============================================================================
#  ЖИВЫЕ ЗОНДЫ
# ============================================================================

def link_probe_awg1() -> dict:
    """L0: показания штатного туннеля awg1 (handshake + transfer)."""
    core = _core_module()
    r = core._run(["awg", "show", "awg1"], capture=True, check=False)
    if r.returncode != 0:
        return {"handshake_age": None, "tx": 0, "rx": 0, "up": False}
    data = link_parse_awg_show(r.stdout or "")
    data["up"] = True
    return data


def link_probe_ping_gw(subnet: str) -> dict:
    """L1: ICMP до шлюза exit через awg1 (ядро exit отвечает;
    тот же принцип, что _awgs_cascade_probe_alive в awg_cascade)."""
    core = _core_module()
    base = (subnet or "").split("/")[0].rsplit(".", 1)[0]
    gw = f"{base}.1"
    r = core._run(["ping", "-n", "-I", "awg1", "-c", "2", "-W", "2", gw],
                  capture=True, check=False)
    return {"ok": r.returncode == 0, "gw": gw}


def link_probe_ping_big(probe_host: str = "", count: int = 0,
                        size: int = 0) -> dict:
    """L2: большой поток штатным fwmark-путём транзита.

    ping -m <fwmark каскада> отправляет ICMP с SO_MARK: маршрутный
    lookup видит ip rule fwmark → table 2000 → awg1 → exit → интернет —
    пакет идёт ТОЧНО тем путём, что и транзит пользователей (локальный
    main-маршрут не вмешивается). Ответ возвращается штатным путём.
    ~57 КБ в каждую сторону — за порогом антитуннеля 16–32 КБ: живое
    плечо доживает до конца, режущийся по объёму — теряет пакеты.

    Возвращает {ok, loss_pct|None, sent_bytes, supported}: supported=
    False на системах без ping -m (старый busybox) — зонд честно
    отказывается, а не врёт нулём.
    """
    core = _core_module()
    host = probe_host or AWGS_PROBE_HOST
    cnt = count or AWGS_PROBE_PING_COUNT
    sz = size or AWGS_PROBE_PING_SIZE
    r = core._run(
        ["ping", "-n", "-m", str(AWGS_CASCADE_FWMARK), "-s", str(sz),
         "-c", str(cnt), "-W", "2", host],
        capture=True, check=False)
    if r.returncode not in (0, 1) or "usage" in (r.stderr or "").lower():
        # ping не знает -m — зонд не поддержан этой системой
        return {"ok": False, "loss_pct": None, "sent_bytes": 0,
                "supported": False}
    loss = link_parse_ping_loss((r.stdout or "") + (r.stderr or ""))
    return {
        "ok": r.returncode == 0 and (loss is not None
                                     and loss <= AWGS_PROBE_OK_LOSS_PCT),
        "loss_pct": loss,
        "sent_bytes": cnt * (sz + 28),
        "supported": True,
    }


# ============================================================================
#  КЛАССИФИКАТОР
# ============================================================================

def link_classify(awg1: dict, ping_gw: dict, ping_big: dict) -> str:
    """Показания зондов → код паттерна среды (см. LINK_PATTERNS).

    Чистая функция — таблица решений, тестируется без сервера.
    Порядок вопросов важен: «нет предмета» → «плечо мертво» →
    «направленность» → «поток режется» → «живо/деградация».
    """
    if not awg1.get("up"):
        return "no-tunnel"
    if awg1.get("handshake_age") is None and ping_gw.get("ok") is not True:
        return "udp-dead"

    tx = int(awg1.get("tx") or 0)
    rx = int(awg1.get("rx") or 0)
    # Направленность — по СЧЁТЧИКАМ transfer, а не по пингам: счётчики
    # не врут о том, ЧТО реально прошло через туннель за его жизнь
    # (пинг-GW живёт в обе стороны и в одностороннем плече не отличим).
    if tx > 0 and rx == 0:
        return "one-way-out"
    if tx == 0 and rx > 0:
        return "one-way-in"

    # Поток по объёму — большой зонд; если не поддержан — вердикт по
    # дешёвым зондам (handshake жив = плечо как-то живо).
    if ping_big.get("supported") is False:
        return "big-ping-unsupported"
    if ping_big.get("loss_pct") is not None \
            and ping_big["loss_pct"] >= AWGS_PROBE_CUT_LOSS_PCT:
        return "stream-cut"
    if ping_big.get("loss_pct") is not None \
            and ping_big["loss_pct"] > AWGS_PROBE_OK_LOSS_PCT:
        return "flaky"
    return "bidirectional-ok"


# ============================================================================
#  МАТРИЦА «СИМПТОМ → ВЕРДИКТ → РЕКОМЕНДАЦИЯ»
# ============================================================================

# Единая точка правды для TUI-отчёта и тестов. recommendation — текст
# для человека (что делать и каким пунктом меню); canon — параграф FAQ,
# на который опирается вердикт. split_direction: True = паттерн лечится
# split-режимом (пунктом меню awg_split_direction).
LINK_PATTERNS: dict = {
    "bidirectional-ok": {
        "label": "Плечо живо в обе стороны",
        "verdict": "Штатный туннель каскада пропускает поток 50+ КБ в "
                   "обе стороны без потерь. Разбирать нечего.",
        "recommendation": "Оставить штатный режим. Если DPI палит "
                          "сигнатуру WG/AWG на провайдере — AWG-меню → "
                          "пункт 7 (ротация обфускации) или carrier-пресет "
                          "оператора (awg_presets).",
        "split_direction": False,
        "canon": "RU_NODE_CASCADE_FAQ §7 (curl-тест плеча)",
    },
    "one-way-out": {
        "label": "Исходящее живо, входящее мертво",
        "verdict": "Счётчики туннеля: байты уходят, ответы не "
                   "возвращаются (sent > 0, received = 0). Классический "
                   "симптом «отправить можем — принять нет».",
        "recommendation": "Разделить подслучаи зондом L1 (пинг шлюза): "
                          "если короткие пакеты ходят в ОБЕ стороны — "
                          "Split-direction (п.8): пара однонаправленных "
                          "туннелей. Если же короткие тоже режутся в обе "
                          "стороны (двусторонний кат ~25 пакетов — кейс "
                          "Виталия) — AWG-релей (п.9): один туннель + "
                          "UDP-релей, флоу сеется DNS-прелеюдией.",
        "split_direction": True,
        "canon": "кейс Виталия (FAQ AWG_SPLIT_DIRECTION §1, "
                 "AWG_KERNEL_RELAY §1)",
    },
    "one-way-in": {
        "label": "Входящее живо, исходящее мертво",
        "verdict": "Обратная редкость: ответы приходят, запросы тонут "
                   "(sent = 0, received > 0).",
        "recommendation": "Split-direction рассчитан на обычную "
                          "направленность и здесь не поможет: переносить "
                          "exit к живому хостеру (детектор цензуры → "
                          "список живых AS).",
        "split_direction": False,
        "canon": "RU_NODE_CASCADE_FAQ §9.1",
    },
    "stream-cut": {
        "label": "Поток режется по объёму (антитуннель)",
        "verdict": "Handshake жив, короткие пробы проходят, но поток "
                   "50+ КБ теряется почти целиком — обрыв на 16–32 КБ, "
                   "сигнатура «Read Timeout at 16KB/…» из FAQ.",
        "recommendation": "Канон: перенос exit к живому хостеру (детектор "
                          "цензуры; §9.1). Паллиативы по подслучаям: "
                          "Split-direction (п.8) — если короткие пакеты "
                          "ходят в обе стороны; AWG-релей (п.9) — если "
                          "двусторонний кат валит и handshake'ы (кейс "
                          "Виталия). Проверить зондом после включения.",
        "split_direction": True,   # паллиатив, канон — перенос exit
        "canon": "RU_NODE_CASCADE_FAQ §3.2, §9.2; FAQ AWG_KERNEL_RELAY §3",
    },
    "udp-dead": {
        "label": "UDP-плечо мертво целиком",
        "verdict": "Handshake не сходится, шлюз exit не отвечает: рез "
                   "по протоколу/порту на всём плече.",
        "recommendation": "Перенос exit к живому хостеру (детектор "
                          "цензуры) или другой транспорт; смена порта — "
                          "ротация обфускации (пункт 7) — иногда "
                          "спасает при портовом фильтре.",
        "split_direction": False,
        "canon": "RU_NODE_CASCADE_FAQ §9.1",
    },
    "flaky": {
        "label": "Деградация: потери в серой зоне",
        "verdict": "Большой поток проходит частично (потери 20–80%) — "
                   "плечо живо, но канал деградировал (перегрузка "
                   "аплинка хостера — кейс Mevspace — или мягкий DPI).",
        "recommendation": "Смотреть повторным прогоном зонда в разное "
                          "время; при стойких потерях — перенос exit. "
                          "Мульти-exit каскад (пункт 5) разводит трафик "
                          "по запасным выходам.",
        "split_direction": False,
        "canon": "RU_NODE_CASCADE_FAQ §5 (дрейф профиля)",
    },
    "big-ping-unsupported": {
        "label": "Зонд большого потока не поддержан",
        "verdict": "ping этой системы не умеет -m (SO_MARK): полный "
                   "вердикт по объёму недоступен, оценка — по handshake "
                   "и шлюзу.",
        "recommendation": "Плечо живо; для вердикта по антитуннелю — "
                          "curl-тест большого файла вручную (FAQ §7 "
                          "шаг 5) со стороны клиента.",
        "split_direction": False,
        "canon": "RU_NODE_CASCADE_FAQ §7 шаг 5",
    },
    "no-tunnel": {
        "label": "Каскад не поднят",
        "verdict": "Туннель awg1 отсутствует — зондить нечего.",
        "recommendation": "Сначала настроить каскад (меню каскада → "
                          "пункты 1–2), затем повторить зонд.",
        "split_direction": False,
        "canon": "—",
    },
}


def link_recommend(pattern: str) -> dict:
    """Код паттерна → запись матрицы (LABEL/вердикт/рекомендация).

    Неизвестный код (регресс) → no-tunnel-запись с честной пометкой:
    матрица — единая точка правды, неизвестного паттерна быть не может,
    но модуль обязан ответить, а не упасть.
    """
    entry = LINK_PATTERNS.get(pattern)
    if entry is None:
        return {
            "label": "Неизвестный паттерн",
            "verdict": f"Классификатор вернул неизвестный код {pattern!r} "
                       f"— сообщите разработчикам.",
            "recommendation": "Повторите зонд; при повторении — репорт.",
            "split_direction": False,
            "canon": "—",
        }
    return entry


# ============================================================================
#  ПРОГОН ВСЕЙ ЛЕСТНИЦЫ + TUI-ОТЧЁТ
# ============================================================================

def link_probe_run(probe_host: str = "") -> dict:
    """Полный прогон лестницы L0→L2 + классификация.

    Ничего не переключает: только чтение показаний и пинги. Результат —
    словарь-отчёт (для меню, логов и тестов):
      {awg1, ping_gw, ping_big, pattern, recommendation, ts}
    """
    from datetime import datetime, timezone

    awg1 = link_probe_awg1()
    state = awgs_state_load()
    subnet = state.get("cascade_subnet", "")
    ping_gw = link_probe_ping_gw(subnet) if awg1.get("up") else \
        {"ok": False, "gw": ""}
    # Большой зонд имеет смысл только при живом handshake: в мёртвом
    # плече он просто ничего не ответит и облепит вердикт «udp-dead».
    ping_big = (link_probe_ping_big(probe_host)
                if awg1.get("handshake_age") is not None
                else {"ok": False, "loss_pct": None, "sent_bytes": 0,
                      "supported": True})
    pattern = link_classify(awg1, ping_gw, ping_big)
    return {
        "awg1": awg1,
        "ping_gw": ping_gw,
        "ping_big": ping_big,
        "pattern": pattern,
        "recommendation": link_recommend(pattern),
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def _fmt_bytes(n: int) -> str:
    n = int(n or 0)
    for unit in ("Б", "КиБ", "МиБ", "ГиБ"):
        if n < 1024 or unit == "ГиБ":
            return f"{n} {unit}" if unit == "Б" else f"{n / 1024:.1f} {unit}"
        n //= 1024
    return f"{n} Б"


def link_probe_report(report: dict) -> None:
    """TUI-отчёт зонда: портрет поля + вердикт + рекомендация.

    Печатает рамкой (канон _box_*): показания зондов, паттерн и совет
    из матрицы. Не бросает исключений при печати.
    """
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    GREEN, RED, YELLOW, DIM, CYAN, NC = (core.GREEN, core.RED, core.YELLOW,
                                         core.DIM, core.CYAN, core.NC)

    awg1 = report.get("awg1") or {}
    big = report.get("ping_big") or {}
    gw = report.get("ping_gw") or {}
    rec = report.get("recommendation") or {}

    _fmt = lambda v, ok, bad: (f"{GREEN}{v}{NC}" if ok
                               else (f"{RED}{v}{NC}" if bad else f"{YELLOW}{v}{NC}"))

    print()
    _box_top("ЗОНД ПЛЕЧА КАСКАДА • ПОРТРЕТ ПОЛЯ")
    _box_row()
    _box_row(f"  Туннель awg1 (штатный, до активного exit):")
    if awg1.get("up"):
        age = awg1.get("handshake_age")
        age_str = (f"{age} сек назад" if age is not None
                   else "handshake не сходился")
        _box_row(f"    handshake:  {_fmt(age_str, age is not None and age <= 300, age is None)}")
        tx, rx = awg1.get("tx", 0), awg1.get("rx", 0)
        tx_col = GREEN if tx > 0 else DIM
        rx_col = GREEN if rx > 0 else RED
        _box_row(f"    исходящий:  {tx_col}↑{_fmt_bytes(tx)}{NC}   "
                 f"входящий:  {rx_col}↓{_fmt_bytes(rx)}{NC}")
        _box_row(f"    шлюз exit ({gw.get('gw', '?')}): "
                 + _fmt("жив" if gw.get("ok") else "не отвечает",
                        bool(gw.get("ok")), not gw.get("ok")))
    else:
        _box_row(f"    {RED}не поднят{NC}")
    _box_row()
    if big.get("supported") is False:
        _box_row(f"  Большой поток (50+ КБ через fwmark-путь): "
                 f"{DIM}ping без -m — не поддержан{NC}")
    elif big.get("loss_pct") is not None:
        loss = big["loss_pct"]
        _box_row(f"  Большой поток ({_fmt_bytes(big.get('sent_bytes', 0))} "
                 f"через fwmark-путь): потери "
                 + _fmt(f"{loss}%", loss <= AWGS_PROBE_OK_LOSS_PCT,
                        loss >= AWGS_PROBE_CUT_LOSS_PCT))
    else:
        _box_row(f"  Большой поток: {DIM}пропущен (плечо без handshake){NC}")
    _box_row()
    pat = report.get("pattern", "no-tunnel")
    _box_row(f"  {CYAN}Вердикт:{NC} {rec.get('label', pat)}")
    _box_row(f"    {rec.get('verdict', '')}")
    _box_row(f"  {CYAN}Рекомендация:{NC} {rec.get('recommendation', '')}")
    if rec.get("canon") and rec.get("canon") != "—":
        _box_row(f"    {DIM}канон: {rec.get('canon')}{NC}")
    _box_bottom()


def do_link_probe_interactive() -> None:
    """Пункт меню: прогнать зонд и показать отчёт (плюс — в лог)."""
    core = _core_module()
    report = link_probe_run()
    link_probe_report(report)
    try:
        core.log_to_file("INFO",
                         "link_probe: pattern="
                         + str(report.get("pattern")))
    except Exception:
        pass
