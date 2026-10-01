"""
chimera/modules/mieru_traffic_presets.py — Mieru traffic pattern presets.

ЕДИНЫЙ ИСТОЧНИК ИСТИНЫ паттернов обфускации: конфиги здесь — те же
JSON-объекты, что mieru.py кладёт в server.json mita (поле
trafficPattern). База для клиентской выдачи (base64-protobuf в
mierus://-ссылках и поле traffic_pattern sing-box JSON) кодирует ИМЕННО
их — клиент и сервер всегда получают один и тот же TrafficPattern.

ПРОТОКОЛЬНАЯ ССЫЛКА (base.proto, mieru):
  TrafficPattern { seed=1, unlockAll=2, tcpFragment=3, nonce=4, padding=5 }
  TCPFragment    { enable=1, maxSleepMs=2 }
  NoncePattern   { type=1, applyToAllUDPPacket=2, minLen=3, maxLen=4 }
  PaddingPattern { maxMiddlePaddingLen=1, maxEndPaddingLen=2 }
  NonceType: RANDOM=0, PRINTABLE=1, FIXED=2
    (PRINTABLE=1 подтверждён живым `mita export traffic-pattern` на
    прод-ноде 02.10.2026: конфиг {"type":"NONCE_TYPE_PRINTABLE"} →
    байты 22 02 08 01)

Правила сериализации (сверены с живым mita export, aggressive):
- поле со значением false/0/отсутствующим в JSON → НЕ сериализуется
  (proto3 без presence: mita export для aggressive не содержит ни
  unlockAll, ни applyToAllUDPPacket, ни seed — только то, что задано);
- вложенный message без живых полей → опускается целиком;
- порядок полей — по номеру (encode_message сортирует), совпадает с
  выводом mita export.

ЭТАЛОН ЖИВОЙ НОДЫ (aggressive, 02.10.2026, 203.0.113.101):
  mita export traffic-pattern → GgQIARAUIgIIASoFCEAQgAE=
  наш encode_traffic_pattern(aggressive) → байт-в-байт то же самое
  (закреплено в tests/test_mieru_traffic_presets.py).
"""
from __future__ import annotations

import base64

# Протобуф типы полей для сериализатора
TCP_FRAGMENT_TYPES = {
    1: 0,  # enable: bool (varint)
    2: 0,  # maxSleepMs: int32 (varint)
}

NONCE_PATTERN_TYPES = {
    1: 0,  # type: NonceType enum (varint)
    2: 0,  # applyToAllUDPPacket: bool (varint)
    3: 0,  # minLen: int32 (varint)
    4: 0,  # maxLen: int32 (varint)
}

PADDING_PATTERN_TYPES = {
    1: 0,  # maxMiddlePaddingLen: int32 (varint)
    2: 0,  # maxEndPaddingLen: int32 (varint)
}

TRAFFIC_PATTERN_TYPES = {
    1: 0,  # seed: int32 (varint)
    2: 0,  # unlockAll: bool (varint)
    3: 2,  # tcpFragment: embedded message (length-delimited)
    4: 2,  # nonce: embedded message (length-delimited)
    5: 2,  # padding: embedded message (length-delimited)
}

# NonceType: имя из JSON mita → номер proto-енума
# (PRINTABLE=1 — живой mita export; RANDOM=0/FIXED=2 — по base.proto)
NONCE_TYPE_MAP = {
    "NONCE_TYPE_UNSPECIFIED": 0,
    "NONCE_TYPE_RANDOM": 0,
    "NONCE_TYPE_PRINTABLE": 1,
    "NONCE_TYPE_FIXED": 2,
}


def encode_varint(value: int) -> bytes:
    """Кодирует целое число в формат Varint (Base128)."""
    if value < 0:
        value &= 0xffffffffffffffff
    out = bytearray()
    while True:
        towrite = value & 0x7f
        value >>= 7
        if value > 0:
            out.append(towrite | 0x80)
        else:
            out.append(towrite)
            break
    return bytes(out)


def encode_message(fields: dict, field_types: dict) -> bytes:
    """Минимальный сериализатор Protobuf сообщений.

    Значения None (и только None) пропускаются; фильтрацию false/0
    выполняет вызывающий код (encode_traffic_pattern) — протокол
    mieru не сериализует незаданные поля."""
    out = bytearray()
    for field_num, val in sorted(fields.items()):
        if val is None:
            continue
        wire_type = field_types[field_num]
        header = (field_num << 3) | wire_type
        out.extend(encode_varint(header))

        if wire_type == 0:
            if isinstance(val, bool):
                val_int = 1 if val else 0
            else:
                val_int = int(val)
            out.extend(encode_varint(val_int))
        elif wire_type == 2:
            if isinstance(val, bytes):
                out.extend(encode_varint(len(val)))
                out.extend(val)
    return bytes(out)


# ═════════════════════════════════════════════════════════════════════════════
#  Определения пресетов (= конфиги server.json mita, см. mieru.py
#  _MIERU_TRAFFIC_PRESETS — таблица ссылается сюда, один источник)
# ═════════════════════════════════════════════════════════════════════════════

PRESETS = {
    "disabled": {
        "name": "disabled",
        "label": "🔓 Disabled (Без обфускации)",
        "description": "Минимум оверхеда, максимальная скорость и производительность",
        "config": None,  # trafficPattern не добавляется ни в server.json, ни клиентам
    },
    "basic": {
        "name": "basic",
        "label": "🔒 Basic (Базовый)",
        "description": "Printable-нонсы (по умолчанию)",
        "config": {
            "nonce": {"type": "NONCE_TYPE_PRINTABLE"},
        },
    },
    "medium": {
        "name": "medium",
        "label": "🔒 Medium (Средний)",
        "description": "Нонсы + TCP-фрагментация с задержкой 10 мс",
        "config": {
            "nonce": {"type": "NONCE_TYPE_PRINTABLE"},
            "tcpFragment": {"enable": True, "maxSleepMs": 10},
        },
    },
    "aggressive": {
        "name": "aggressive",
        "label": "🔒 Aggressive (Максимальный)",
        "description": "Нонсы + фрагментация 20 мс + паддинг 64/128",
        "config": {
            "nonce": {"type": "NONCE_TYPE_PRINTABLE"},
            "tcpFragment": {"enable": True, "maxSleepMs": 20},
            "padding": {"maxMiddlePaddingLen": 64, "maxEndPaddingLen": 128},
        },
    }
}


def encode_traffic_pattern(config: dict) -> str:
    """JSON-конфиг trafficPattern (формат server.json mita) → base64-protobuf.

    Кодирует ТОЛЬКО заданные поля (false/0/отсутствующие пропускаются),
    пустые вложенные message опускаются — байт-в-байт повторяет вывод
    `mita export traffic-pattern` для тех же данных (эталон: aggressive,
    живая нода 02.10.2026). Пустой/None конфиг → '' (паттерна нет)."""
    if not config:
        return ""

    # seed (поле 1) — в пресетах не используется, но пользовательский
    # JSON может его нести
    seed = config.get("seed")
    if seed is None or int(seed) == 0:
        seed = None

    # unlockAll (поле 2) — сериализуем только явное True: mita export
    # не содержит поля, когда серверный JSON его не задал
    unlock = True if config.get("unlockAll") else None

    # tcpFragment (поле 3)
    tcp_bytes = None
    tcp = config.get("tcpFragment") or {}
    if tcp:
        enable = 1 if tcp.get("enable") else None
        sleep_ms = tcp.get("maxSleepMs")
        sleep_ms = int(sleep_ms) if sleep_ms else None
        tcp_bytes = encode_message({1: enable, 2: sleep_ms},
                                   TCP_FRAGMENT_TYPES)
        if not tcp_bytes:
            tcp_bytes = None

    # nonce (поле 4)
    nonce_bytes = None
    nonce = config.get("nonce") or {}
    if nonce:
        raw_type = nonce.get("type", 0)
        if isinstance(raw_type, str):
            ntype = NONCE_TYPE_MAP.get(raw_type.upper(), 0)
        else:
            ntype = int(raw_type or 0)
        apply_all = 1 if nonce.get("applyToAllUDPPacket") else None
        min_len = nonce.get("minLen")
        min_len = int(min_len) if min_len else None
        max_len = nonce.get("maxLen")
        max_len = int(max_len) if max_len else None
        nonce_bytes = encode_message(
            {1: ntype if ntype else None, 2: apply_all,
             3: min_len, 4: max_len}, NONCE_PATTERN_TYPES)
        if not nonce_bytes:
            nonce_bytes = None

    # padding (поле 5)
    pad_bytes = None
    pad = config.get("padding") or {}
    if pad:
        mid = pad.get("maxMiddlePaddingLen")
        mid = int(mid) if mid else None
        end = pad.get("maxEndPaddingLen")
        end = int(end) if end else None
        pad_bytes = encode_message({1: mid, 2: end}, PADDING_PATTERN_TYPES)
        if not pad_bytes:
            pad_bytes = None

    tp_bytes = encode_message(
        {1: seed, 2: unlock, 3: tcp_bytes, 4: nonce_bytes, 5: pad_bytes},
        TRAFFIC_PATTERN_TYPES)
    return base64.b64encode(tp_bytes).decode("utf-8")


def get_preset_base64(name: str) -> str:
    """base64-блоб пресета для клиентской выдачи (mierus://, sing-box JSON).

    Кодирует ТОТ ЖЕ конфиг, что сервер mita применяет под этим именем
    (PRESETS = источник server.json). '' — паттерн не задан (disabled
    или пустой конфиг): параметр/поле в выдачу не добавляется."""
    preset = PRESETS.get(name)
    if not preset:
        preset = PRESETS["basic"]  # fallback
    return encode_traffic_pattern(preset.get("config"))


def list_presets() -> list[dict]:
    """Возвращает список всех доступных пресетов."""
    return list(PRESETS.values())


def get_preset(name: str) -> dict:
    """Возвращает информацию о пресете по его имени."""
    preset = PRESETS.get(name)
    if not preset:
        preset = PRESETS["basic"]
    return preset
